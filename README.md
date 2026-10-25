# Mandate Clearing

A signed, machine-verifiable mandate (power of attorney) for AI agents that purchase on behalf of a user.

The mandate token occupies a single field in any payment rail — x402, Google AP2, Mastercard Verifiable Intent, or a Solana instruction. The verifier is the same everywhere. NORTH7 is the first operator, not the owner.

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
sdk/                    TypeScript ESM SDK (Node 20+)
  src/
    verifier.ts         Pure verifyOrder function (no I/O)
    canonical.ts        Canonical JSON serialization + SHA-256
    crypto.ts           Ed25519 (tweetnacl) + ES256 (WebCrypto P-256)
    mandate.ts          issueMandate, attestOrder, signCart
    nonce.ts            NonceRegistry interface
    types.ts            All TypeScript types
    demo.ts             Full lifecycle demo

services/
  verifier/             Verifier as a service (wraps pure verifyOrder)
    src/server.ts       POST /verify, GET /verdicts/:id, GET /agents/:pubkey/reputation
    src/middleware.ts    Express middleware (X-Mandate + X-Attestation headers)
    src/pg-store.ts     Postgres: verdicts + ledger (atomic transactions)
    src/pg-nonce.ts     Postgres-backed NonceRegistry
    src/schema.sql      Database schema

apps/
  approve/              Principal approval page
    src/server.ts       GET /approve?req=<base64>, POST /approve (signs mandate)
    public/index.html   Approval UI (shows constraints, not the prompt)
  shop/                 Demo merchant (API credit shop)
    src/server.ts       GET /catalog, POST /cart (signCart), POST /pay
  agent/                Reference agent CLI
    src/cli.ts          agent mandate, agent buy, agent buy --evil

adapters/
  x402/                 x402 payment rail adapter
  ap2/                  Google AP2 adapter (SD-JWT ↔ Mandate)
  verifiable-intent/    Mastercard Verifiable Intent adapter

program/                Solana Anchor program (Rust) — escrow, Ed25519 introspection
schema/                 JSON Schema 2020-12
docs/interop.md         Field-by-field mapping: Mandate ↔ VI ↔ AP2
tests/e2e/              End-to-end integration tests
```

## Running

### Quick start (no database)

```bash
# Install and build SDK
cd sdk && npm install && npx tsc

# Run unit tests
npm test                    # 50 SDK tests

# Run adapter tests
cd ../adapters/x402 && npm install && npm test      # 7 tests
cd ../ap2 && npm install && npm test                 # 10 tests
cd ../verifiable-intent && npm install && npm test   # 12 tests
```

### Full flow (all services in-process)

```bash
# Install all services
cd apps/approve && npm install
cd ../shop && npm install
cd ../../services/verifier && npm install
cd ../../tests/e2e && npm install

# Run E2E tests (starts all services, runs 4 scenarios)
cd tests/e2e && npm test
```

The E2E test runs all services in-process without Docker or Postgres. The verifier falls back to in-memory state when no database is available.

### Production (with Postgres)

```bash
# Start Postgres
docker run -d --name mandate-pg -e POSTGRES_USER=mandate -e POSTGRES_PASSWORD=mandate -e POSTGRES_DB=mandate -p 5432:5432 postgres:16

# Initialize schema
psql postgresql://mandate:mandate@localhost:5432/mandate < services/verifier/src/schema.sql

# Start services
DATABASE_URL=postgresql://mandate:mandate@localhost:5432/mandate PORT=3200 node --import tsx services/verifier/src/server.ts
PORT=3100 node --import tsx apps/approve/src/server.ts
PORT=3300 node --import tsx apps/shop/src/server.ts

# Use agent CLI
node --import tsx apps/agent/src/cli.ts mandate --merchant north7.ai --categories api-credits --max-total 10000 --hours 24
node --import tsx apps/agent/src/cli.ts buy --sku credits-1000 --qty 2
node --import tsx apps/agent/src/cli.ts buy --evil   # must get 402
```

## Tests

| Module | Tests | What it covers |
|--------|-------|---------------|
| SDK (verifier + canonical + crypto) | 50 | All 18 violation codes, liability assignment, canonicalization, Ed25519 + ES256 |
| x402 adapter | 7 | Payment flow, replay, wrong merchant, state tracking |
| AP2 adapter | 10 | SD-JWT parsing, constraint mapping, round-trip, ed25519 rejection |
| VI adapter | 12 | 3-layer chain, cart translation, autonomous/immediate mode, round-trip |
| Approve service | 3 | Request decode, mandate signing, signature validity |
| Verifier service | 6 | APPROVE, REJECT (merchant), REJECT (budget), health |
| Shop service | 6 | Catalog, cart signing, signature validity, unknown SKU |
| E2E flow | 4 | approve→buy→APPROVE, replay→REJECT, evil→REJECT, budget→EXCEEDED |
| **Total** | **98** | |

Solana Anchor program has 8 attack tests (CPI guard, replay, scope checks) but requires the Anchor toolchain to run.

## Verification Order

The verifier checks in strict order, with early return:

1. **Mandate signature** — fail → `REJECT`, liability `NONE`, never debit
2. **Attestation** — signature, agent match, hash match, cart signature, replay — fail → `REJECT`, liability `AGENT_PROVIDER`
3. **Time window** — mandate validity — fail → `REJECT`, liability `AGENT_PROVIDER`
4. **Order integrity** — total = sum of items, currency match — fail → `REJECT`, liability `AGENT_PROVIDER`
5. **Scope** — merchant, category, SKU, qty, item price, per-order limit, budget, order count — fail → `REJECT`, liability `AGENT_PROVIDER`

## Status

### What works

- **SDK**: Complete, 50 tests, pure `verifyOrder` function. Ed25519 + ES256.
- **Verifier service**: Wraps SDK in HTTP server. Postgres persistence for nonces, ledger, verdicts. Atomic transactions prevent race conditions.
- **Approval page**: Signs mandates with ed25519. Shows constraints to principal. WebAuthn/Passkey support planned (currently ed25519 fallback).
- **Shop**: Signs carts, serves catalog. Ready to integrate with real north7.ai credit endpoints.
- **Agent CLI**: Full lifecycle from mandate request to purchase. Evil mode for testing.
- **E2E flow**: All 4 scenarios pass — approve, replay, evil, budget exceeded.
- **Adapters**: x402, Google AP2, Mastercard VI. Pure translation, original signatures preserved.
- **Solana program**: Code complete (escrow, settle, dispute, release, revoke). Not deployed.

### What does NOT work yet

- **Solana Devnet deploy**: Anchor toolchain not installed on server. Program ID `EKRPj4JfLPuBWuqVmC1bA3S4Z7PdR4gAzdqUk36Xt1zV` is localnet only.
- **WebAuthn/Passkey signing**: Approval page uses ed25519 fallback. Browser Passkey integration not implemented.
- **Docker Compose**: Not yet created. Services run in-process or standalone.
- **Redis NonceRegistry**: Interface defined, implementation not written.
- **Key rotation**: No mechanism for rotating principal, agent, or merchant keys.
- **Security audit**: No external audit. Crypto uses tweetnacl (Ed25519) and WebCrypto (ES256). Review the code before production use.
- **Real payment integration**: The shop is a demo. No real money moves.

## Demo

- **Landing page**: [landing.html](landing.html) — interactive explanation with live constraint checking
- **CLI demo**: `cd sdk && npm run demo` — full lifecycle with real Ed25519 signatures (issue → sign → attest → verify → replay)
- **Reference flow**: `cd tests/e2e && npm test` — approve → buy → replay → evil → budget exceeded

## Interop

- **Google AP2**: We parse AP2 Open Mandates (SD-JWT) and map their constraint types to our `Constraints`; we add the liability model and dispute window that AP2 does not have.
- **Mastercard Verifiable Intent**: We consume VI's 3-layer SD-JWT chain in autonomous mode, extract constraints and agent key binding; we add `traceHash`, `modelVersion`, and liability assignment that VI does not define.

Both adapters are pure translation — `verifyOrder` is never modified. See [docs/interop.md](docs/interop.md) for the full field-by-field mapping.

## License

MIT — NORTH7 Paradox Software LTD, Ireland
