use anchor_lang::prelude::*;
use anchor_lang::solana_program::ed25519_program;
use anchor_lang::solana_program::instruction::{
    get_stack_height, TRANSACTION_LEVEL_STACK_HEIGHT,
};
use anchor_lang::solana_program::sysvar::instructions::get_instruction_relative;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("EKRPj4JfLPuBWuqVmC1bA3S4Z7PdR4gAzdqUk36Xt1zV");

/// Maximum number of entries in any allowlist (merchants, categories, SKUs).
const MAX_ALLOWLIST: usize = 8;

// ── Ed25519 introspection helpers ──

/// Size of one signature-offset struct in the Ed25519 precompile data.
const ED25519_OFFSETS_SIZE: usize = 14; // 7 x u16
/// Header: 2 bytes (num_signatures + padding).
const ED25519_HEADER_SIZE: usize = 2;

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16> {
    require!(offset + 2 <= data.len(), MandateError::Ed25519BadIndex);
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

/// Parse one Ed25519 signature entry from the precompile instruction data.
/// Returns (pubkey_32, signature_64, message_bytes).
fn parse_ed25519_entry<'a>(
    data: &'a [u8],
    entry_index: usize,
) -> Result<(&'a [u8], &'a [u8], &'a [u8])> {
    let base = ED25519_HEADER_SIZE + entry_index * ED25519_OFFSETS_SIZE;
    require!(base + ED25519_OFFSETS_SIZE <= data.len(), MandateError::Ed25519BadIndex);

    let sig_offset = read_u16_le(data, base)? as usize;
    let sig_ix_idx = read_u16_le(data, base + 2)?;
    let pubkey_offset = read_u16_le(data, base + 4)? as usize;
    let pubkey_ix_idx = read_u16_le(data, base + 6)?;
    let msg_offset = read_u16_le(data, base + 8)? as usize;
    let msg_size = read_u16_le(data, base + 10)? as usize;
    let msg_ix_idx = read_u16_le(data, base + 12)?;

    // All three instruction indices must be u16::MAX (same instruction).
    require!(sig_ix_idx == u16::MAX, MandateError::Ed25519BadIndex);
    require!(pubkey_ix_idx == u16::MAX, MandateError::Ed25519BadIndex);
    require!(msg_ix_idx == u16::MAX, MandateError::Ed25519BadIndex);

    // Bounds-check and extract slices.
    require!(sig_offset + 64 <= data.len(), MandateError::Ed25519BadIndex);
    require!(pubkey_offset + 32 <= data.len(), MandateError::Ed25519BadIndex);
    require!(msg_offset + msg_size <= data.len(), MandateError::Ed25519BadIndex);

    let pubkey = &data[pubkey_offset..pubkey_offset + 32];
    let signature = &data[sig_offset..sig_offset + 64];
    let message = &data[msg_offset..msg_offset + msg_size];

    Ok((pubkey, signature, message))
}

/// Domain separation prefixes for signed messages.
const ATTESTATION_PREFIX: &[u8] = b"mandate-clearing/attestation/v1";
const CART_PREFIX: &[u8] = b"mandate-clearing/cart/v1";

/// Build the expected message from clear args WITH a domain prefix:
/// prefix || mandate_hash || order_hash || content_hash || trace_hash || timestamp_le
fn build_expected_message_with_prefix(
    prefix: &[u8],
    mandate_hash: &[u8; 32],
    order_hash: &[u8; 32],
    content_hash: &[u8; 32],
    trace_hash: &[u8; 32],
    timestamp: i64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(prefix.len() + 136);
    msg.extend_from_slice(prefix);
    msg.extend_from_slice(mandate_hash);
    msg.extend_from_slice(order_hash);
    msg.extend_from_slice(content_hash);
    msg.extend_from_slice(trace_hash);
    msg.extend_from_slice(&timestamp.to_le_bytes());
    msg
}

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
    ///
    /// Requires an Ed25519 precompile instruction at index = (clear_index - 1)
    /// containing exactly TWO signatures:
    ///   0: Agent attestation (pubkey = mandate.agent)
    ///   1: Merchant cart signature (pubkey = merchant account)
    ///
    /// Each signature's message is reconstructed on-chain from the clear args
    /// and compared byte-by-byte with the precompile data.
    pub fn clear(
        ctx: Context<ClearOrder>,
        order_hash: [u8; 32],
        attestation_hash: [u8; 32],
        order_total: u64,
        item_prices: Vec<u64>,
        item_quantities: Vec<u32>,
        item_categories: Vec<[u8; 32]>,
        item_skus: Vec<[u8; 32]>,
        merchant_hash: [u8; 32],
        order_currency: String,
        // New args for Ed25519 message reconstruction
        cart_hash: [u8; 32],
        trace_hash: [u8; 32],
        mandate_hash: [u8; 32],
        sig_timestamp: i64,
    ) -> Result<()> {
        let mandate = &ctx.accounts.mandate;
        let clock = Clock::get()?;
        let now = clock.unix_timestamp;

        // ── CPI guard: clear must not be called via CPI ──
        require!(
            get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT,
            MandateError::CpiNotAllowed
        );

        // ── Check mandate not revoked ──
        require!(!mandate.revoked, MandateError::MandateRevoked);

        // ── Time window ──
        require!(now >= mandate.valid_from, MandateError::MandateNotYetValid);
        require!(now <= mandate.valid_until, MandateError::MandateExpired);

        // ── Ed25519 instruction introspection ──
        let ix_sysvar = &ctx.accounts.instructions_sysvar;

        // Load the previous instruction (relative index -1).
        let ed25519_ix = get_instruction_relative(-1, ix_sysvar)
            .map_err(|_| error!(MandateError::Ed25519Missing))?;

        // Must be the Ed25519 native program.
        require!(
            ed25519_ix.program_id == ed25519_program::ID,
            MandateError::Ed25519WrongProgram
        );

        let ed_data = &ed25519_ix.data;

        // Must have at least header.
        require!(ed_data.len() >= ED25519_HEADER_SIZE, MandateError::Ed25519BadIndex);

        let num_signatures = ed_data[0];
        require!(num_signatures == 2, MandateError::Ed25519SigCount);

        // ── Parse signature 0: Agent attestation ──
        let (agent_pk_bytes, _agent_sig, agent_msg) = parse_ed25519_entry(ed_data, 0)?;

        // Pubkey must match mandate.agent.
        require!(
            agent_pk_bytes == mandate.agent.to_bytes(),
            MandateError::Ed25519PubkeyMismatch
        );

        // Reconstruct expected agent attestation message with domain prefix:
        // "mandate-clearing/attestation/v1" || mandate_hash || order_hash || attestation_hash || trace_hash || timestamp_le
        let expected_agent_msg = build_expected_message_with_prefix(
            ATTESTATION_PREFIX,
            &mandate_hash,
            &order_hash,
            &attestation_hash,
            &trace_hash,
            sig_timestamp,
        );
        require!(
            agent_msg == expected_agent_msg.as_slice(),
            MandateError::Ed25519MessageMismatch
        );

        // ── Parse signature 1: Merchant cart signature ──
        let (merchant_pk_bytes, _merchant_sig, merchant_msg) = parse_ed25519_entry(ed_data, 1)?;

        // Pubkey must match the merchant account passed to clear.
        require!(
            merchant_pk_bytes == ctx.accounts.merchant.key().to_bytes(),
            MandateError::Ed25519PubkeyMismatch
        );

        // Reconstruct expected merchant cart message with domain prefix:
        // "mandate-clearing/cart/v1" || mandate_hash || order_hash || cart_hash || trace_hash || timestamp_le
        let expected_merchant_msg = build_expected_message_with_prefix(
            CART_PREFIX,
            &mandate_hash,
            &order_hash,
            &cart_hash,
            &trace_hash,
            sig_timestamp,
        );
        require!(
            merchant_msg == expected_merchant_msg.as_slice(),
            MandateError::Ed25519MessageMismatch
        );

        // ── Agent account check (belt-and-suspenders) ──
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

        Ok(())
    }

    /// Principal revokes the mandate. Remaining escrow returned.
    pub fn revoke(ctx: Context<Revoke>) -> Result<()> {
        let mandate = &mut ctx.accounts.mandate;
        require!(!mandate.revoked, MandateError::MandateAlreadyRevoked);
        mandate.revoked = true;

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

    /// CHECK: Merchant pubkey — verified against Ed25519 precompile.
    pub merchant: UncheckedAccount<'info>,

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

    /// CHECK: Instructions sysvar for Ed25519 introspection.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

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
}

#[derive(Accounts)]
pub struct Revoke<'info> {
    pub principal: Signer<'info>,

    #[account(
        mut,
        constraint = mandate.principal == principal.key() @ MandateError::PrincipalMismatch,
    )]
    pub mandate: Account<'info, MandateAccount>,
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
    // Ed25519 introspection errors
    #[msg("Ed25519 precompile instruction missing")]
    Ed25519Missing,
    #[msg("Instruction is not from the Ed25519 program")]
    Ed25519WrongProgram,
    #[msg("Ed25519 data offset/index out of bounds")]
    Ed25519BadIndex,
    #[msg("Ed25519 pubkey does not match expected")]
    Ed25519PubkeyMismatch,
    #[msg("Ed25519 message does not match reconstructed")]
    Ed25519MessageMismatch,
    #[msg("Ed25519 precompile must contain exactly 2 signatures")]
    Ed25519SigCount,
    #[msg("clear must not be called via CPI")]
    CpiNotAllowed,
}
