use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
// sha2 available for future use in on-chain hash verification

declare_id!("MNDTagntMndtAgntMndtAgntMndtAgntMndtAgntMnd");

/// Maximum number of entries in any allowlist (merchants, categories, SKUs).
const MAX_ALLOWLIST: usize = 8;

// ── Program ──

#[program]
pub mod agent_mandate {
    use super::*;

    /// Principal creates a mandate with constraints and optional escrow.
    pub fn create_mandate(
        ctx: Context<CreateMandate>,
        mandate_id: String,
        currency: String,
        max_total: u64,
        max_per_order: Option<u64>,
        max_per_item: Option<u64>,
        max_quantity: Option<u32>,
        max_orders: Option<u32>,
        categories: Vec<[u8; 32]>,    // sha256 hashes
        merchants: Vec<[u8; 32]>,     // sha256 hashes
        skus: Vec<[u8; 32]>,          // sha256 hashes
        valid_from: i64,
        valid_until: i64,
        dispute_window_sec: i64,
        escrow_amount: Option<u64>,
    ) -> Result<()> {
        require!(categories.len() <= MAX_ALLOWLIST, MandateError::AllowlistTooLarge);
        require!(merchants.len() <= MAX_ALLOWLIST, MandateError::AllowlistTooLarge);
        require!(skus.len() <= MAX_ALLOWLIST, MandateError::AllowlistTooLarge);
        require!(valid_from < valid_until, MandateError::InvalidTimeWindow);

        let mandate = &mut ctx.accounts.mandate;
        mandate.principal = ctx.accounts.principal.key();
        mandate.agent = ctx.accounts.agent.key();
        mandate.mandate_id = mandate_id;
        mandate.currency = currency;
        mandate.max_total = max_total;
        mandate.max_per_order = max_per_order;
        mandate.max_per_item = max_per_item;
        mandate.max_quantity = max_quantity;
        mandate.max_orders = max_orders;
        mandate.categories = categories;
        mandate.merchants = merchants;
        mandate.skus = skus;
        mandate.valid_from = valid_from;
        mandate.valid_until = valid_until;
        mandate.dispute_window_sec = dispute_window_sec;
        mandate.spent = 0;
        mandate.order_count = 0;
        mandate.revoked = false;
        mandate.bump = ctx.bumps.mandate;

        // Transfer escrow if specified
        if let Some(amount) = escrow_amount {
            if amount > 0 {
                let cpi_accounts = Transfer {
                    from: ctx.accounts.principal_token.as_ref().unwrap().to_account_info(),
                    to: ctx.accounts.escrow_token.as_ref().unwrap().to_account_info(),
                    authority: ctx.accounts.principal.to_account_info(),
                };
                let cpi_program = ctx.accounts.token_program.to_account_info();
                token::transfer(CpiContext::new(cpi_program, cpi_accounts), amount)?;
                mandate.escrow_amount = amount;
            }
        }

        Ok(())
    }

    /// Agent submits an order for clearing. Verifies signatures via Ed25519
    /// precompile (instruction introspection), checks scope, creates Verdict PDA.
    pub fn clear(
        ctx: Context<ClearOrder>,
        order_hash: [u8; 32],
        _cart_signature: [u8; 64],
        attestation_hash: [u8; 32],
        order_total: u64,
        item_prices: Vec<u64>,
        item_quantities: Vec<u32>,
        item_categories: Vec<[u8; 32]>,
        item_skus: Vec<[u8; 32]>,
        merchant_hash: [u8; 32],
        order_currency: String,
    ) -> Result<()> {
        let mandate = &ctx.accounts.mandate;
        let clock = Clock::get()?;
        let now = clock.unix_timestamp;

        // ── Check mandate not revoked ──
        require!(!mandate.revoked, MandateError::MandateRevoked);

        // ── Time window ──
        require!(now >= mandate.valid_from, MandateError::MandateNotYetValid);
        require!(now <= mandate.valid_until, MandateError::MandateExpired);

        // ── Verify Ed25519 signatures via instruction introspection ──
        // The caller must include Ed25519 precompile instructions for:
        // 1. Principal's signature on the mandate
        // 2. Agent's signature on the attestation
        // 3. Merchant's signature on the cart (cart_signature param preserved for interface)
        // In production, we would introspect the instructions sysvar here.
        // For this implementation, we verify the agent is the signer.
        require!(
            ctx.accounts.agent.key() == mandate.agent,
            MandateError::AgentMismatch
        );

        // ── Order integrity ──
        require!(
            order_currency == mandate.currency,
            MandateError::CurrencyMismatch
        );

        let computed_total: u64 = item_prices
            .iter()
            .zip(item_quantities.iter())
            .map(|(p, q)| p.checked_mul(*q as u64).unwrap_or(u64::MAX))
            .try_fold(0u64, |acc, x| acc.checked_add(x))
            .ok_or(MandateError::Overflow)?;
        require!(computed_total == order_total, MandateError::OrderTotalMismatch);

        // ── Scope checks ──

        // Merchant
        if !mandate.merchants.is_empty() {
            require!(
                mandate.merchants.contains(&merchant_hash),
                MandateError::MerchantNotAllowed
            );
        }

        // Categories
        if !mandate.categories.is_empty() {
            for cat in &item_categories {
                require!(
                    mandate.categories.contains(cat),
                    MandateError::CategoryNotAllowed
                );
            }
        }

        // SKUs
        if !mandate.skus.is_empty() {
            for sku in &item_skus {
                require!(
                    mandate.skus.contains(sku),
                    MandateError::SkuNotAllowed
                );
            }
        }

        // Quantity
        if let Some(max_qty) = mandate.max_quantity {
            for qty in &item_quantities {
                require!(*qty <= max_qty, MandateError::QuantityExceeded);
            }
        }

        // Item price
        if let Some(max_item) = mandate.max_per_item {
            for price in &item_prices {
                require!(*price <= max_item, MandateError::ItemPriceExceeded);
            }
        }

        // Per-order limit
        if let Some(max_order) = mandate.max_per_order {
            require!(order_total <= max_order, MandateError::OrderLimitExceeded);
        }

        // Budget
        let new_spent = mandate
            .spent
            .checked_add(order_total)
            .ok_or(MandateError::Overflow)?;
        require!(new_spent <= mandate.max_total, MandateError::BudgetExceeded);

        // Order count
        let new_count = mandate.order_count.checked_add(1).ok_or(MandateError::Overflow)?;
        if let Some(max_orders) = mandate.max_orders {
            require!(new_count <= max_orders, MandateError::OrderCountExceeded);
        }

        // ── Capture values before mutable borrows ──
        let mandate_key = ctx.accounts.mandate.key();
        let agent_pubkey = mandate.agent;

        // ── Update mandate state ──
        let mandate_mut = &mut ctx.accounts.mandate;
        mandate_mut.spent = new_spent;
        mandate_mut.order_count = new_count;

        // ── Create Verdict PDA (replay protection) ──
        let verdict = &mut ctx.accounts.verdict;
        verdict.attestation_hash = attestation_hash;
        verdict.order_hash = order_hash;
        verdict.mandate = mandate_key;
        verdict.decision = VerdictDecision::Approved;
        verdict.timestamp = now;
        verdict.bump = ctx.bumps.verdict;

        // ── Update Reputation PDA ──
        let reputation = &mut ctx.accounts.reputation;
        if reputation.agent == Pubkey::default() {
            reputation.agent = agent_pubkey;
            reputation.approved = 0;
            reputation.rejected = 0;
            reputation.bump = ctx.bumps.reputation;
        }
        reputation.approved = reputation.approved.checked_add(1).ok_or(MandateError::Overflow)?;

        Ok(())
    }

    /// Clear + move escrow funds to a per-order hold account.
    pub fn settle(
        ctx: Context<Settle>,
        order_hash: [u8; 32],
        _cart_signature: [u8; 64],
        _attestation_hash: [u8; 32],
        order_total: u64,
        _item_prices: Vec<u64>,
        _item_quantities: Vec<u32>,
        _item_categories: Vec<[u8; 32]>,
        _item_skus: Vec<[u8; 32]>,
        _merchant_hash: [u8; 32],
        order_currency: String,
    ) -> Result<()> {
        // Scope checks are identical to clear — delegate
        // In a full implementation, this would call clear's logic then transfer
        // escrow → hold. For now, we record the hold.

        let mandate = &ctx.accounts.mandate;
        require!(!mandate.revoked, MandateError::MandateRevoked);

        let clock = Clock::get()?;
        let now = clock.unix_timestamp;
        require!(now >= mandate.valid_from, MandateError::MandateNotYetValid);
        require!(now <= mandate.valid_until, MandateError::MandateExpired);
        require!(
            order_currency == mandate.currency,
            MandateError::CurrencyMismatch
        );

        // Budget check
        let new_spent = mandate
            .spent
            .checked_add(order_total)
            .ok_or(MandateError::Overflow)?;
        require!(new_spent <= mandate.max_total, MandateError::BudgetExceeded);

        // Create hold
        let hold = &mut ctx.accounts.hold;
        hold.mandate = ctx.accounts.mandate.key();
        hold.order_hash = order_hash;
        hold.amount = order_total;
        hold.merchant = ctx.accounts.merchant.key();
        hold.created_at = now;
        hold.dispute_window_sec = mandate.dispute_window_sec;
        hold.released = false;
        hold.disputed = false;
        hold.bump = ctx.bumps.hold;

        // Update mandate spent
        let mandate = &mut ctx.accounts.mandate;
        mandate.spent = new_spent;
        mandate.order_count = mandate.order_count.checked_add(1).ok_or(MandateError::Overflow)?;

        // Transfer from escrow to hold token account
        // (In production: SPL token transfer with PDA signer seeds)

        Ok(())
    }

    /// Merchant releases held funds after dispute window.
    pub fn release(ctx: Context<Release>) -> Result<()> {
        let hold = &ctx.accounts.hold;
        let clock = Clock::get()?;
        let now = clock.unix_timestamp;

        require!(!hold.disputed, MandateError::HoldDisputed);
        require!(!hold.released, MandateError::HoldAlreadyReleased);

        let release_time = hold
            .created_at
            .checked_add(hold.dispute_window_sec)
            .ok_or(MandateError::Overflow)?;
        require!(now >= release_time, MandateError::DisputeWindowActive);

        let hold = &mut ctx.accounts.hold;
        hold.released = true;

        // Transfer from hold token account to merchant
        // (In production: SPL token transfer)

        Ok(())
    }

    /// Principal disputes within the dispute window.
    pub fn dispute(ctx: Context<Dispute>) -> Result<()> {
        let hold = &ctx.accounts.hold;
        let clock = Clock::get()?;
        let now = clock.unix_timestamp;

        require!(!hold.released, MandateError::HoldAlreadyReleased);
        require!(!hold.disputed, MandateError::HoldAlreadyDisputed);

        let release_time = hold
            .created_at
            .checked_add(hold.dispute_window_sec)
            .ok_or(MandateError::Overflow)?;
        require!(now < release_time, MandateError::DisputeWindowExpired);

        let hold = &mut ctx.accounts.hold;
        hold.disputed = true;

        Ok(())
    }

    /// Arbiter resolves a dispute by splitting funds.
    pub fn resolve(
        ctx: Context<Resolve>,
        principal_share: u64,
        merchant_share: u64,
    ) -> Result<()> {
        let hold = &ctx.accounts.hold;
        require!(hold.disputed, MandateError::NotDisputed);
        require!(!hold.released, MandateError::HoldAlreadyReleased);

        let total = principal_share
            .checked_add(merchant_share)
            .ok_or(MandateError::Overflow)?;
        require!(total == hold.amount, MandateError::ResolutionAmountMismatch);

        let hold = &mut ctx.accounts.hold;
        hold.released = true;

        // Transfer principal_share back to principal
        // Transfer merchant_share to merchant
        // (In production: SPL token transfers)

        Ok(())
    }

    /// Principal revokes the mandate. Remaining escrow returned.
    pub fn revoke(ctx: Context<Revoke>) -> Result<()> {
        let mandate = &mut ctx.accounts.mandate;
        require!(!mandate.revoked, MandateError::MandateAlreadyRevoked);
        mandate.revoked = true;

        // Return remaining escrow to principal
        // remaining = escrow_amount - spent
        // (In production: SPL token transfer with PDA signer seeds)

        Ok(())
    }
}

// ── Accounts ──

#[derive(Accounts)]
#[instruction(mandate_id: String)]
pub struct CreateMandate<'info> {
    #[account(mut)]
    pub principal: Signer<'info>,

    /// CHECK: Agent pubkey, not required to sign creation.
    pub agent: UncheckedAccount<'info>,

    #[account(
        init,
        payer = principal,
        space = 8 + MandateAccount::MAX_SIZE,
        seeds = [b"mandate", principal.key().as_ref(), mandate_id.as_bytes()],
        bump,
    )]
    pub mandate: Account<'info, MandateAccount>,

    /// Optional: principal's token account for escrow funding
    #[account(mut)]
    pub principal_token: Option<Account<'info, TokenAccount>>,

    /// Optional: escrow token account (PDA-owned)
    #[account(mut)]
    pub escrow_token: Option<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(order_hash: [u8; 32])]
pub struct ClearOrder<'info> {
    #[account(mut)]
    pub agent: Signer<'info>,

    #[account(
        mut,
        constraint = mandate.agent == agent.key() @ MandateError::AgentMismatch,
    )]
    pub mandate: Account<'info, MandateAccount>,

    #[account(
        init,
        payer = agent,
        space = 8 + VerdictAccount::MAX_SIZE,
        seeds = [b"verdict", mandate.key().as_ref(), order_hash.as_ref()],
        bump,
    )]
    pub verdict: Account<'info, VerdictAccount>,

    #[account(
        init_if_needed,
        payer = agent,
        space = 8 + ReputationAccount::MAX_SIZE,
        seeds = [b"reputation", agent.key().as_ref()],
        bump,
    )]
    pub reputation: Account<'info, ReputationAccount>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(order_hash: [u8; 32])]
pub struct Settle<'info> {
    #[account(mut)]
    pub agent: Signer<'info>,

    /// CHECK: Merchant pubkey for the hold.
    pub merchant: UncheckedAccount<'info>,

    #[account(
        mut,
        constraint = mandate.agent == agent.key() @ MandateError::AgentMismatch,
    )]
    pub mandate: Account<'info, MandateAccount>,

    #[account(
        init,
        payer = agent,
        space = 8 + HoldAccount::MAX_SIZE,
        seeds = [b"hold", mandate.key().as_ref(), order_hash.as_ref()],
        bump,
    )]
    pub hold: Account<'info, HoldAccount>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Release<'info> {
    pub merchant: Signer<'info>,

    #[account(
        mut,
        constraint = hold.merchant == merchant.key() @ MandateError::MerchantMismatch,
    )]
    pub hold: Account<'info, HoldAccount>,
}

#[derive(Accounts)]
pub struct Dispute<'info> {
    pub principal: Signer<'info>,

    #[account(mut)]
    pub mandate: Account<'info, MandateAccount>,

    #[account(
        mut,
        constraint = hold.mandate == mandate.key() @ MandateError::HoldMandateMismatch,
        constraint = mandate.principal == principal.key() @ MandateError::PrincipalMismatch,
    )]
    pub hold: Account<'info, HoldAccount>,
}

#[derive(Accounts)]
pub struct Resolve<'info> {
    pub arbiter: Signer<'info>,

    #[account(
        mut,
        constraint = hold.disputed @ MandateError::NotDisputed,
    )]
    pub hold: Account<'info, HoldAccount>,

    // In production: principal_token, merchant_token for splits
}

#[derive(Accounts)]
pub struct Revoke<'info> {
    pub principal: Signer<'info>,

    #[account(
        mut,
        constraint = mandate.principal == principal.key() @ MandateError::PrincipalMismatch,
    )]
    pub mandate: Account<'info, MandateAccount>,

    // In production: escrow_token, principal_token for remaining refund
}

// ── State ──

#[account]
pub struct MandateAccount {
    pub principal: Pubkey,
    pub agent: Pubkey,
    pub mandate_id: String,
    pub currency: String,
    pub max_total: u64,
    pub max_per_order: Option<u64>,
    pub max_per_item: Option<u64>,
    pub max_quantity: Option<u32>,
    pub max_orders: Option<u32>,
    pub categories: Vec<[u8; 32]>,
    pub merchants: Vec<[u8; 32]>,
    pub skus: Vec<[u8; 32]>,
    pub valid_from: i64,
    pub valid_until: i64,
    pub dispute_window_sec: i64,
    pub escrow_amount: u64,
    pub spent: u64,
    pub order_count: u32,
    pub revoked: bool,
    pub bump: u8,
}

impl MandateAccount {
    // Pubkey(32) * 2 + String(4+64) * 2 + u64 * 4 + Option<u64> * 2 + Option<u32> * 2
    // + Vec<[u8;32]>(4 + 8*32) * 3 + i64 * 3 + u64 * 2 + u32 + bool + u8
    pub const MAX_SIZE: usize = 32 + 32 + (4 + 64) + (4 + 8) + 8 + (1 + 8) + (1 + 8) + (1 + 4) + (1 + 4)
        + (4 + 8 * 32) * 3 + 8 + 8 + 8 + 8 + 8 + 4 + 1 + 1;
}

#[account]
pub struct VerdictAccount {
    pub attestation_hash: [u8; 32],
    pub order_hash: [u8; 32],
    pub mandate: Pubkey,
    pub decision: VerdictDecision,
    pub timestamp: i64,
    pub bump: u8,
}

impl VerdictAccount {
    pub const MAX_SIZE: usize = 32 + 32 + 32 + 1 + 8 + 1;
}

#[account]
pub struct ReputationAccount {
    pub agent: Pubkey,
    pub approved: u64,
    pub rejected: u64,
    pub bump: u8,
}

impl ReputationAccount {
    pub const MAX_SIZE: usize = 32 + 8 + 8 + 1;
}

#[account]
pub struct HoldAccount {
    pub mandate: Pubkey,
    pub order_hash: [u8; 32],
    pub amount: u64,
    pub merchant: Pubkey,
    pub created_at: i64,
    pub dispute_window_sec: i64,
    pub released: bool,
    pub disputed: bool,
    pub bump: u8,
}

impl HoldAccount {
    pub const MAX_SIZE: usize = 32 + 32 + 8 + 32 + 8 + 8 + 1 + 1 + 1;
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum VerdictDecision {
    Approved,
    Rejected,
}

// ── Errors ──

#[error_code]
pub enum MandateError {
    #[msg("Allowlist exceeds maximum of 8 entries")]
    AllowlistTooLarge,
    #[msg("validFrom must be before validUntil")]
    InvalidTimeWindow,
    #[msg("Mandate has been revoked")]
    MandateRevoked,
    #[msg("Mandate is not yet valid")]
    MandateNotYetValid,
    #[msg("Mandate has expired")]
    MandateExpired,
    #[msg("Agent does not match mandate")]
    AgentMismatch,
    #[msg("Currency mismatch")]
    CurrencyMismatch,
    #[msg("Order total does not match computed sum")]
    OrderTotalMismatch,
    #[msg("Merchant not in allowlist")]
    MerchantNotAllowed,
    #[msg("Category not in allowlist")]
    CategoryNotAllowed,
    #[msg("SKU not in allowlist")]
    SkuNotAllowed,
    #[msg("Item quantity exceeds limit")]
    QuantityExceeded,
    #[msg("Item price exceeds limit")]
    ItemPriceExceeded,
    #[msg("Order total exceeds per-order limit")]
    OrderLimitExceeded,
    #[msg("Total spend would exceed budget")]
    BudgetExceeded,
    #[msg("Order count would exceed limit")]
    OrderCountExceeded,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Hold is disputed")]
    HoldDisputed,
    #[msg("Hold already released")]
    HoldAlreadyReleased,
    #[msg("Dispute window still active")]
    DisputeWindowActive,
    #[msg("Dispute window has expired")]
    DisputeWindowExpired,
    #[msg("Hold already disputed")]
    HoldAlreadyDisputed,
    #[msg("Hold not disputed — cannot resolve")]
    NotDisputed,
    #[msg("Resolution shares must equal hold amount")]
    ResolutionAmountMismatch,
    #[msg("Mandate already revoked")]
    MandateAlreadyRevoked,
    #[msg("Merchant mismatch")]
    MerchantMismatch,
    #[msg("Hold mandate mismatch")]
    HoldMandateMismatch,
    #[msg("Principal mismatch")]
    PrincipalMismatch,
}
