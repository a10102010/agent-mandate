# Interoperability Mapping: Agent Mandate ↔ Verifiable Intent ↔ AP2

> Generated 2026-10-25 from reading the actual specs:
> - Agent Mandate: `sdk/src/types.ts`, `sdk/src/verifier.ts`
> - Verifiable Intent (VI): `github.com/agent-intent/verifiable-intent` (commit at time of clone)
> - AP2: `github.com/google-agentic-commerce/AP2` (commit at time of clone)

## 1. Structural Comparison

| Concept | Agent Mandate | Verifiable Intent (VI) | AP2 (Google) |
|---------|--------------|----------------------|-------------|
| Format | Canonical JSON + Ed25519/ES256 | SD-JWT (ES256 only) | SD-JWT (ES256 only) |
| Layers | 1 (Mandate + Attestation) | 3 (L1 Issuer → L2 User → L3 Agent) | 3 (Intent → Checkout → Payment) |
| Delegation | Principal signs Mandate, Agent signs Attestation | Issuer → User → Agent chain via `cnf` key binding | User signs Open Mandates, Agent signs Closed via `cnf` |
| Selective Disclosure | None (all-or-nothing) | Full SD-JWT with per-claim disclosure | Full SD-JWT with per-claim disclosure |
| Signature Input | `canonicalize(obj)` → SHA-256 → sign bytes | `Base64url(header).Base64url(payload)` → sign ASCII | `Base64url(header).Base64url(payload)` → sign ASCII |
| Replay Protection | NonceRegistry (attestation hash) | `nonce` + `aud` per layer, `sd_hash` binding | `nonce` in Key Binding JWT |
| Liability Model | Explicit (NONE / AGENT_PROVIDER / PRINCIPAL) | **Not present** | **Not present** |
| Escrow | Solana on-chain program | **Not present** | **Not present** |
| Verdict | VerdictAccount (on-chain) | **Not present** (Receipts are informational) | **Not present** (Receipts are informational) |
| Cart Signing | Merchant signs Order → `cartSignature` | Merchant signs Checkout JWT | Merchant signs Checkout JWT |
| Modes | Single mode | Immediate (2-layer) + Autonomous (3-layer) | Human Present + Human Not Present |

## 2. Field Mapping: Mandate

### 2.1 Our Mandate → VI User Mandate (L2)

| Our Field | Type | VI Field | VI Location | Mapping |
|-----------|------|----------|-------------|---------|
| `mandate.version` | `'1'` | — | — | ❌ Not present. VI uses `vct` strings for versioning |
| `mandate.mandateId` | string | `nonce` | L2 payload | ⚠️ Convention: VI `nonce` serves as unique ID + replay protection |
| `mandate.principal.scheme` | `'ed25519'\|'es256'` | `alg` | L1 header + L2 `cnf.jwk` | ⚠️ Convention: VI is ES256-only; ed25519 mandates cannot map |
| `mandate.principal.pubkey` | Base58 | `cnf.jwk` | L1 payload | ⚠️ Convention: Base58 → JWK conversion required |
| `mandate.agent.id` | string | `kid` | L2 checkout/payment mandate `cnf.kid` | ⚠️ Convention: VI uses JWK `kid` as agent identifier |
| `mandate.agent.scheme` | `'ed25519'\|'es256'` | `alg` | L3 header | ⚠️ Convention: ES256-only in VI |
| `mandate.agent.pubkey` | Base58 | `cnf.jwk` | L2 checkout/payment mandate `cnf.jwk` | ⚠️ Convention: Base58 → JWK |
| `mandate.constraints.currency` | ISO 4217 | `payment_amount.currency` (immediate) / `payment.amount_range.currency` (autonomous) | L2 payment mandate / constraint | ✅ Direct (ISO 4217 in both) |
| `mandate.constraints.maxTotal` | minor units | `payment.budget.max` | L2 constraint | ✅ Direct (both use integer minor units) |
| `mandate.constraints.maxPerOrder` | minor units | `payment.amount_range.max` | L2 constraint | ✅ Direct |
| `mandate.constraints.maxPerItem` | minor units | — | — | ❌ Not present in VI constraints |
| `mandate.constraints.maxQuantity` | number | `checkout.line_items.items[].quantity` | L2 constraint | ⚠️ Convention: VI per-item quantity, not global |
| `mandate.constraints.maxOrders` | number | `payment.agent_recurrence.max_occurrences` | L2 constraint | ⚠️ Convention: VI recurrence is broader (frequency + max) |
| `mandate.constraints.categories` | string[] | — | — | ❌ Not present. VI has no category allowlist |
| `mandate.constraints.merchants` | string[] | `checkout.allowed_merchants.allowed[].id` | L2 constraint | ✅ Direct (both are merchant ID allowlists) |
| `mandate.constraints.skus` | string[] | `checkout.line_items.items[].acceptable_items[].id` | L2 constraint | ⚠️ Convention: VI nests SKUs inside line-item constraints |
| `mandate.validFrom` | unix sec | `iat` | L2 payload | ⚠️ Convention: VI `iat` ≈ validFrom (issued-at, not explicit "valid from") |
| `mandate.validUntil` | unix sec | `exp` | L2 payload | ✅ Direct |
| `mandate.nonce` | string ≥16 | `nonce` | L2 payload | ✅ Direct (both use random nonces) |
| `mandate.policy.liabilityModel` | `'mandate-scope-v1'` | — | — | ❌ **Not present in VI** |
| `mandate.policy.disputeWindowSec` | number | — | — | ❌ **Not present in VI** |

### 2.2 Our Mandate → AP2 Open Mandates

| Our Field | Type | AP2 Field | AP2 Location | Mapping |
|-----------|------|-----------|-------------|---------|
| `mandate.version` | `'1'` | `vct` | Open mandate payload | ⚠️ Convention: AP2 uses `mandate.checkout.open.1` / `mandate.payment.open.1` |
| `mandate.mandateId` | string | — | — | ❌ Not present. AP2 uses SD-JWT hash chains for identification |
| `mandate.principal.pubkey` | Base58 | Signing key of Trusted Surface | SD-JWT issuer | ⚠️ Convention: AP2 user signs via Trusted Surface, key in L1 `cnf.jwk` |
| `mandate.agent.pubkey` | Base58 | `cnf.jwk` | Open mandate payload | ⚠️ Convention: Base58 → JWK |
| `mandate.agent.id` | string | `cnf.jwk.kid` | Open mandate payload | ⚠️ Convention |
| `mandate.constraints.currency` | ISO 4217 | `payment.amount_range.currency` | Payment constraint | ✅ Direct |
| `mandate.constraints.maxTotal` | minor units | `payment.budget.max` | Payment constraint | ✅ Direct |
| `mandate.constraints.maxPerOrder` | minor units | `payment.amount_range.max` | Payment constraint | ✅ Direct |
| `mandate.constraints.maxPerItem` | minor units | — | — | ❌ Not present in AP2 |
| `mandate.constraints.maxQuantity` | number | `checkout.line_items.items[].quantity` | Checkout constraint | ⚠️ Convention: per-item, not global |
| `mandate.constraints.maxOrders` | number | `payment.agent_recurrence.max_occurrences` | Payment constraint | ⚠️ Convention |
| `mandate.constraints.categories` | string[] | — | — | ❌ **Not present in AP2** |
| `mandate.constraints.merchants` | string[] | `checkout.allowed_merchants.allowed[].id` | Checkout constraint | ✅ Direct |
| `mandate.constraints.skus` | string[] | `checkout.line_items.items[].acceptable_items[].id` | Checkout constraint | ⚠️ Convention |
| `mandate.validFrom` | unix sec | `iat` | Open mandate payload | ⚠️ Convention |
| `mandate.validUntil` | unix sec | `exp` | Open mandate payload | ✅ Direct |
| `mandate.nonce` | string | Key Binding JWT `nonce` | KB-JWT payload | ⚠️ Convention: AP2 nonce is in KB-JWT, not mandate body |
| `mandate.policy.liabilityModel` | string | — | — | ❌ **Not present in AP2** |
| `mandate.policy.disputeWindowSec` | number | — | — | ❌ **Not present in AP2** |

## 3. Field Mapping: Order / Cart

| Our Field | Type | VI Field | AP2 Field | Mapping |
|-----------|------|----------|-----------|---------|
| `order.orderId` | string | — | `checkout_jwt.order_id` | ⚠️ VI has no order ID; AP2 has it in Checkout JWT |
| `order.merchant` | string | `cart.merchant_name` / L3b merchant | `checkout_jwt.merchant.id` | ⚠️ Convention: our string vs their structured object |
| `order.currency` | ISO 4217 | `cart.currency` | `checkout_jwt.currency` | ✅ Direct |
| `order.items[].sku` | string | `cart.items[].sku` | `checkout_jwt.line_items[].product.id` | ⚠️ Convention: different nesting |
| `order.items[].category` | string | — | — | ❌ Not present in either |
| `order.items[].unitPrice` | minor units | `cart.items[].price` (string!) | `checkout_jwt.line_items[].product.price` (float!) | ⚠️ Convention: VI uses decimal strings, AP2 uses floats, we use integer minor units |
| `order.items[].qty` | number | `cart.items[].quantity` | `checkout_jwt.line_items[].quantity` | ✅ Direct |
| `order.total` | minor units | `cart.total` (string) | `checkout_jwt.total_price` (float) | ⚠️ Convention: type conversion required |
| `order.createdAt` | unix sec | — | — | ❌ Not present in either |
| `signedOrder.merchantPubkey` | Base58 | Merchant signing key (JWK) | Merchant JWT signing key | ⚠️ Convention: key format differs |
| `signedOrder.cartSignature` | Base58 | JWT signature (part of checkout_jwt) | JWT signature (part of checkout_jwt) | ⚠️ Convention: we sign canonical JSON, they sign JWT |

## 4. Field Mapping: Attestation

| Our Field | Type | VI Equivalent | AP2 Equivalent | Mapping |
|-----------|------|--------------|----------------|---------|
| `attestation.version` | `'1'` | — | — | ❌ Not present |
| `attestation.agentId` | string | L3 `kid` header | KB-JWT `kid` header | ⚠️ Convention |
| `attestation.agentPubkey` | Base58 | L2 mandate `cnf.jwk` | Open mandate `cnf.jwk` | ⚠️ Convention |
| `attestation.modelVersion` | string | — | — | ❌ **Not present in either** (unique to us) |
| `attestation.mandateHash` | hex SHA-256 | L3 `sd_hash` (base64url SHA-256) | KB-JWT `sd_hash` (base64url SHA-256) | ⚠️ Convention: hex vs base64url encoding |
| `attestation.orderHash` | hex SHA-256 | `checkout_hash` (base64url SHA-256 of checkout_jwt) | `checkout_hash` (base64url SHA-256 of checkout_jwt) | ⚠️ Convention: we hash canonical Order, they hash JWT |
| `attestation.cartHash` | hex SHA-256 | Same as `checkout_hash` | Same as `checkout_hash` | ⚠️ Convention |
| `attestation.traceHash` | hex SHA-256 | — | — | ❌ **Not present in either** (unique to us) |
| `attestation.timestamp` | unix sec | L3 `iat` | KB-JWT `iat` | ✅ Direct |
| `signedAttestation.signature` | Base58 Ed25519/ES256 | L3 JWT signature | KB-JWT signature | ⚠️ Convention: format differs (Base58 vs JWT) |

## 5. Field Mapping: Verdict / Receipt

| Our Field | Type | VI Equivalent | AP2 Equivalent | Mapping |
|-----------|------|--------------|----------------|---------|
| `verifyResult.decision` | `APPROVE\|REJECT` | — | Receipt `status` (`Success\|Error`) | ⚠️ Convention: AP2 receipt is post-settlement, our verdict is pre-settlement |
| `verifyResult.liability` | `PRINCIPAL\|AGENT_PROVIDER\|NONE` | — | — | ❌ **Not present in either** |
| `verifyResult.violations[]` | ViolationCode + detail | `ConstraintCheckResult.violations[]` | Receipt `error` + `error_description` | ⚠️ Convention: different granularity |
| `verifyResult.remainingBudget` | minor units | — | — | ❌ Not present (budget tracking is network-enforced in AP2) |

## 6. What They Have That We Don't

| Feature | VI | AP2 | Impact |
|---------|-----|-----|--------|
| **SD-JWT selective disclosure** | Full support, per-claim granularity | Full support | We expose all-or-nothing; privacy-sensitive fields cannot be hidden per-verifier |
| **Issuer credential (L1)** | Card issuer (Mastercard) signs identity + payment instrument | Via Credential Provider | We have no issuer layer; principal is self-sovereign |
| **Payment instrument binding** | `payment_instrument` in mandate | `payment_instrument` in Payment Mandate | We have no concept of card/bank account binding |
| **Recurrence / frequency** | `payment.agent_recurrence` (DAILY, WEEKLY, etc.) | `payment.agent_recurrence` | Our `maxOrders` is count-only, no frequency |
| **Execution date window** | — | `payment.execution_date` (not_before, not_after) | We use `validFrom`/`validUntil` on mandate, not per-payment |
| **PISP (Payment Initiation Service Provider)** | — | `pisp` object in Payment Mandate | We have no intermediary concept |
| **Risk data** | `risk_data` in L2 payment mandate | `risk_data` in Payment Mandate | We have no risk signal passthrough |
| **Checkout JWT (merchant-signed cart)** | Merchant signs full cart as JWT | Merchant signs checkout as JWT | We sign canonical JSON Order, not JWT |
| **Multi-pair mandates** | Multiple checkout+payment pairs in one L2 | Not specified | We have one mandate → many orders, not many mandates in one credential |
| **Receipt with reference hash** | — | Checkout + Payment Receipts with `reference` | Our Verdict is on-chain, not a portable receipt |
| **Line-item matching (maximal flow)** | `checkout.line_items` with `match_mode` | `checkout.line_items` with flow algorithm | Our SKU allowlist is flat, no per-line-item matching |
| **Prompt summary** | `prompt_summary` in L2 (informational) | — | We have `traceHash` (opaque hash, not readable summary) |

## 7. What We Have That They Don't

| Feature | Description | Why It Matters |
|---------|-------------|----------------|
| **Explicit liability model** | `mandate-scope-v1`: NONE / AGENT_PROVIDER / PRINCIPAL with deterministic assignment | Neither VI nor AP2 assigns liability. They verify constraints but don't say WHO pays when something goes wrong. |
| **Verdict (decision record)** | On-chain VerdictAccount with decision + attestation hash | VI and AP2 have receipts (post-settlement), but no pre-settlement approval record. |
| **Pre-capture gate** | `verifyOrder` runs BEFORE any funds move | AP2 verifies constraints but settlement is a separate flow. VI chain verification is separate from payment. |
| **Escrow with dispute window** | Solana program holds funds, releases after dispute window | Neither has on-chain escrow. Disputes go through traditional card networks. |
| **Pure deterministic verifier** | `verifyOrder` is a pure function (no I/O, no network) | VI's `verify_chain` and AP2's constraint checking could be pure but aren't specified as such. |
| **Category allowlist** | `constraints.categories[]` | Neither VI nor AP2 has product category filtering. Only merchant and SKU allowlists. |
| **Per-item price limit** | `constraints.maxPerItem` | Neither has per-item price caps. Only total/per-order limits. |
| **Agent model version** | `attestation.modelVersion` (e.g., "gpt-4-turbo") | Neither tracks which AI model made the decision. |
| **Trace hash** | `attestation.traceHash` (SHA-256 of prompt/transcript) | Neither includes an audit trail hash of the agent's reasoning. |
| **Domain-separated signatures** | `mandate-clearing/attestation/v1` prefix on-chain | VI and AP2 use standard JWT signing without domain separation. |
| **Cart manipulation detection** | Merchant signs Order, agent includes `cartHash` in attestation | VI and AP2 have `checkout_hash` but bind it differently (JWT hash vs canonical hash). |

## 8. Adapter Feasibility

### 8.1 AP2 → Our System

**Feasible with losses.** An AP2 Open Payment Mandate maps well to our Mandate constraints. The main gaps:

- **SD-JWT → Canonical JSON**: We must parse the SD-JWT, extract claims, and rebuild as our Mandate. Original SD-JWT signatures cannot be verified by our `verifyOrder` (different signing format).
- **No liability**: We assign `mandate-scope-v1` liability to the translated mandate. AP2 has no opinion on liability.
- **Missing fields**: We must inject defaults for `policy.liabilityModel`, `policy.disputeWindowSec`, `traceHash`, `modelVersion`.
- **Categories**: AP2 has no category allowlist. Translated mandates will have `categories: []` (all allowed).
- **maxPerItem**: Not expressible in AP2. Will be omitted.

**Round-trip possible** if we restrict to the intersection of fields. Hash identity requires re-signing (different canonical forms), so the adapter stores the original AP2 SD-JWT alongside our representation.

### 8.2 Our System → AP2

**Feasible with losses.** Our Mandate translates to AP2 Open Checkout + Open Payment Mandates. Gaps:

- **No SD-JWT**: We must wrap our data in SD-JWT format with new signatures.
- **Categories lost**: AP2 has no category constraint type.
- **maxPerItem lost**: AP2 has no per-item price constraint.
- **Liability lost**: AP2 has no liability field. Our liability model is stripped.
- **Escrow/Verdict lost**: AP2 has no on-chain settlement concept.
- **traceHash/modelVersion lost**: AP2 has no equivalent.

### 8.3 VI → Our System

**Feasible with losses.** VI's Autonomous mode (L2+L3) maps to our Mandate+Attestation. Gaps:

- **3 layers → 2**: L1 (issuer credential) has no equivalent. We extract user pubkey and discard issuer chain.
- **SD-JWT signatures**: Cannot be verified by `verifyOrder`. Adapter verifies VI chain separately, then translates.
- **Missing fields**: `traceHash`, `modelVersion`, `categories`, `maxPerItem` not in VI.
- **prompt_summary ≠ traceHash**: VI has readable summary, we have opaque hash. Not convertible.

### 8.4 Our System → VI

**Feasible with losses.** Our Mandate translates to VI L2 (autonomous mode). Gaps:

- **No L1**: We have no issuer credential. Cannot produce a valid 3-layer VI chain.
- **Categories lost**: VI has no category constraint.
- **maxPerItem lost**: VI has no per-item price constraint.
- **Liability/Verdict/Escrow lost**: VI has none of these.
- **Ed25519 mandates**: Cannot map to VI (ES256-only). Adapter MUST reject ed25519.

## 9. Translation Failure Cases

These cases MUST produce clear errors, never silent defaults:

| Case | Error |
|------|-------|
| Ed25519 mandate → VI or AP2 | `UNSUPPORTED_SCHEME: ed25519 not supported by target format (ES256 only)` |
| AP2 mandate with no `payment.budget` → our Mandate | `MISSING_REQUIRED: AP2 mandate has no budget constraint; cannot derive maxTotal` |
| AP2 mandate with no `checkout.allowed_merchants` → our Mandate | OK — `merchants: []` means all allowed (same semantics) |
| VI mandate with `categories` constraint (future) | `UNKNOWN_CONSTRAINT: mandate.checkout.categories not in VI spec` |
| Our mandate with `categories` → AP2/VI | `FIELD_NOT_EXPRESSIBLE: categories allowlist has no equivalent in target format` — logged as warning, not error |
| Our mandate with `maxPerItem` → AP2/VI | `FIELD_NOT_EXPRESSIBLE: maxPerItem has no equivalent in target format` — logged as warning |
| AP2 Closed mandate (Human Present) → our Mandate | `WRONG_MODE: AP2 closed mandates are final transactions, not delegations; use open mandates` |
| VI Immediate mode → our Mandate | `WRONG_MODE: VI immediate mode has no agent delegation; use autonomous mode` |
