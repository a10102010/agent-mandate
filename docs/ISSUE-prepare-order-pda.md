# Split `clear` into `prepare_order` (PDA) + `execute_clear` for dual Ed25519 within TX limit

**Labels:** enhancement, on-chain, tx-size

---

## Problem

The `clear` instruction currently requires up to 14 arguments plus Ed25519 signature verification data. When both the agent signature and the merchant cart signature are included (dual Ed25519), the serialized transaction exceeds Solana's 1232-byte TX limit.

**Current state:** The on-chain program accepts 1 or 2 Ed25519 signatures. In practice, all 3 Devnet runs (2026-11-06) used single-signature mode (`cart_signed: false`) because dual signatures do not fit.

The hosted verifier (off-chain) continues to require the cart signature (`CART_SIG_INVALID`). On-chain, without the cart signature, the category is an agent assertion only — merchant and amount are still verified by the program.

---

## `clear` instruction arguments

| # | Argument | Size (bytes) | Needed on-chain | Could be pre-hashed |
|---|---|---|---|---|
| 1 | `mandate_hash` | 32 | Yes (lookup) | No |
| 2 | `order_hash` | 32 | Yes (replay check) | No |
| 3 | `cart_hash` | 32 | Yes (verify) | No |
| 4 | `trace_hash` | 32 | Yes (record) | No |
| 5 | `merchant` | ~10-64 | Yes (scope check) | Yes |
| 6 | `category` | ~10-32 | Yes (scope check) | Yes |
| 7 | `currency` | 3 | Yes (scope check) | Yes |
| 8 | `amount` | 8 | Yes (scope check + escrow) | No |
| 9 | `nonce` | 32 | Yes (replay) | No |
| 10 | `timestamp` | 8 | Yes (time window) | No |
| 11 | `agent_sig_data` | 64 + overhead | Yes (verify) | No |
| 12 | `cart_sig_data` | 64 + overhead | Optional (verify) | No |
| 13 | `ed25519_ix_index` | 1-2 | Yes (introspect) | No |
| 14 | `item_count` / items | variable | Yes (scope) | Yes |

**Total with dual Ed25519:** ~600-800 bytes of instruction data + 2 Ed25519Instruction entries (~200 bytes each) + accounts (~300 bytes) = exceeds 1232 bytes.

---

## Proposed fix: 2-TX pattern

### TX 1: `prepare_order`

Stores order details in a PDA so they do not need to be passed again in TX 2.

```
prepare_order(
  mandate_hash,      // 32 bytes — seed for PDA lookup
  order_hash,        // 32 bytes
  cart_hash,         // 32 bytes
  trace_hash,        // 32 bytes
  merchant,          // variable
  category,          // variable
  currency,          // 3 bytes
  amount,            // 8 bytes
  nonce,             // 32 bytes
  timestamp,         // 8 bytes
  item_count,        // variable
)
```

Creates an `OrderPDA` seeded by `[mandate_hash, order_hash]`. The PDA stores all order data. No signature verification in this TX — anyone can prepare an order (the data is not sensitive; it only becomes binding when cleared).

### TX 2: `execute_clear`

Reads the `OrderPDA` and verifies signatures.

```
execute_clear(
  // Accounts: mandate_pda, order_pda, escrow, verdict_pda, ...
  // Ed25519 verification instructions: agent + merchant (both fit now)
  ed25519_ix_index,  // 1-2 bytes
)
```

All order data comes from the PDA. The TX only carries signature verification data (~200 bytes per sig) plus a few account references. Dual Ed25519 fits within 1232 bytes.

### Cleanup

The `OrderPDA` is closed after `execute_clear` succeeds (rent returned to payer). If `execute_clear` is never called, the PDA expires after a configurable timeout and can be garbage-collected.

---

## Migration

- The single-TX `clear` instruction remains available for single-signature mode (it already fits).
- The 2-TX pattern is required only for dual Ed25519 (cart_signed: true on-chain).
- No breaking changes to existing mandates or verdicts.
- The verdict PDA gains no new fields; `cart_signed: true` simply becomes achievable on-chain.

---

## Acceptance criteria

1. `prepare_order` creates an `OrderPDA` with all order fields.
2. `execute_clear` reads the `OrderPDA`, verifies dual Ed25519, creates the verdict, and closes the `OrderPDA`.
3. Both TXs individually fit within 1232 bytes.
4. Localnet and Devnet tests pass with dual signatures.
5. Single-signature `clear` continues to work as before.
