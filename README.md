# Agent Mandate

A signed, machine-verifiable mandate (power of attorney) for AI agents that purchase on behalf of a user.

The mandate token occupies a single field in any payment rail — Visa TAP, Mastercard Agent Pay, x402, AP2, or a Solana instruction. The verifier is the same everywhere. The on-chain program will eventually become the neutral checkpoint (no operator, no company).

## Architecture

```
Principal ──signs──► Mandate ──────────────────────────────┐
                        │                                   │
Agent ──attests──► Attestation ──┐                          │
                                 │                          │
Merchant ──signs──► Cart ────────┤                          │
                                 ▼                          ▼
                           ┌──────────┐              ┌──────────┐
                           │ Verifier │◄─────────────│  State   │
                           │  (pure)  │              │ (budget, │
                           └────┬─────┘              │  nonces) │
                                │                    └──────────┘
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
                 APPROVE     REJECT      REJECT
                 PRINCIPAL   AGENT_PRV   NONE
```

## Liability Model: mandate-scope-v1

| Condition | Decision | Liability | Meaning |
|---|---|---|---|
| Mandate signature invalid | REJECT | NONE | Forged mandate, never debit anyone |
| Agent not named in mandate, attestation invalid, replay | REJECT | AGENT_PROVIDER | Agent provider is liable |
| Order outside constraints | REJECT | AGENT_PROVIDER | Agent exceeded its authority |
| Order inside constraints | APPROVE | PRINCIPAL | Normal purchase, right of withdrawal remains |
| Wrong goods delivered | — | Merchant | Standard dispute process, not part of verifier |

## Why not "send the prompt"?

A naive approach would embed the agent's full prompt or conversation in the mandate and have the verifier check whether the purchase matches what the user asked for. This fails for three reasons:

1. **Determinism**: Checking natural language requires an LLM. LLMs are non-deterministic. A verification step that sometimes says yes and sometimes says no for the same input is not a verification step.

2. **Oracle attack**: If the verifier uses an LLM, the agent can craft prompts that trick the verifier LLM into approving out-of-scope purchases. The attack surface is unbounded.

3. **Privacy**: The prompt may contain personal information, preferences, or business context that should not be sent to every payment processor in the chain.

Instead, the mandate defines machine-verifiable constraints (amounts, merchants, categories, quantities). The prompt is included only as a SHA-256 hash (`traceHash`) for post-hoc forensic audit.

## Project Structure

```
schema/             JSON Schema 2020-12 for the mandate format
sdk/                TypeScript ESM SDK (Node 20+)
  src/
    canonical.ts    Canonical JSON serialization + SHA-256
    crypto.ts       Ed25519 (tweetnacl) + ES256 (WebCrypto P-256)
    mandate.ts      issueMandate, attestOrder, signCart, verifications
    verifier.ts     Pure verifyOrder function
    nonce.ts        NonceRegistry interface + InMemory implementation
    types.ts        All TypeScript types
    index.ts        Public API exports
    demo.ts         Full lifecycle demo
    *.test.ts       Tests (node:test)
program/            Solana Anchor program (Rust)
adapters/
  x402/             x402 payment rail adapter
  ap2/              Google AP2 (Agent Payments Protocol) adapter
  verifiable-intent/ Mastercard Verifiable Intent adapter
docs/
  interop.md        Field-by-field mapping: Agent Mandate ↔ VI ↔ AP2
```

## Quick Start

```bash
cd sdk
npm install
npm test          # 46 tests, all liability cases
npm run demo      # Full mandate lifecycle
```

## Verification Order

The verifier checks in strict order, with early return:

1. **Mandate signature** — fail → `REJECT`, liability `NONE`, never debit
2. **Attestation** — signature, agent match, mandate hash match, order hash match, cart signature, replay — fail → `REJECT`, liability `AGENT_PROVIDER`
3. **Time window** — mandate validity — fail → `REJECT`, liability `AGENT_PROVIDER`
4. **Order integrity** — total matches sum of items, currency matches — fail → `REJECT`, liability `AGENT_PROVIDER`
5. **Scope** — merchant, category, SKU, quantity, item price, per-order limit, total budget, order count — fail → `REJECT`, liability `AGENT_PROVIDER`

## Violation Codes

| Code | Description |
|---|---|
| `MANDATE_SIG_INVALID` | Principal's signature on mandate failed verification |
| `ATTESTATION_SIG_INVALID` | Agent's signature on attestation failed verification |
| `ATTESTATION_AGENT_MISMATCH` | Agent in attestation differs from mandate |
| `ATTESTATION_HASH_MISMATCH` | Mandate or order hash in attestation doesn't match |
| `CART_SIG_INVALID` | Merchant's cart signature failed verification |
| `ATTESTATION_REPLAYED` | This attestation was already processed |
| `MANDATE_EXPIRED` | Current time is past validUntil |
| `MANDATE_NOT_YET_VALID` | Current time is before validFrom |
| `ORDER_TOTAL_MISMATCH` | Declared total doesn't match sum of items |
| `CURRENCY_MISMATCH` | Order currency doesn't match mandate |
| `MERCHANT_NOT_ALLOWED` | Merchant not in mandate allowlist |
| `CATEGORY_NOT_ALLOWED` | Item category not in mandate allowlist |
| `SKU_NOT_ALLOWED` | Item SKU not in mandate allowlist |
| `QTY_EXCEEDED` | Item quantity exceeds mandate limit |
| `ITEM_PRICE_EXCEEDED` | Item unit price exceeds mandate limit |
| `ORDER_LIMIT_EXCEEDED` | Order total exceeds per-order limit |
| `BUDGET_EXCEEDED` | Cumulative spend would exceed total budget |
| `ORDER_COUNT_EXCEEDED` | Number of orders would exceed limit |

## Interop

- **Google AP2**: We parse AP2 Open Mandates (SD-JWT) and map their constraint types (`payment.budget`, `payment.amount_range`, `checkout.allowed_merchants`) to our `Constraints`; we add the liability model and dispute window that AP2 does not have.
- **Mastercard Verifiable Intent**: We consume VI's 3-layer SD-JWT chain (Issuer → User → Agent) in autonomous mode, extract constraints and agent key binding, and wrap them in our Mandate format; we add `traceHash`, `modelVersion`, and the `mandate-scope-v1` liability assignment that VI does not define.

Both adapters are pure translation — `verifyOrder` is never modified. See [docs/interop.md](docs/interop.md) for the full field-by-field mapping.

## License

MIT
