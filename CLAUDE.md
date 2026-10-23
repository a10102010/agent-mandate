# CLAUDE.md — Agent Mandate Invariants

These invariants MUST hold across all implementations (SDK, on-chain program, adapters).
Breaking any of them is a security defect.

## Invariant 1: Canonical JSON is the signature input

`canonicalize()` produces the exact bytes that are signed and verified.
Keys are recursively sorted, no whitespace, only safe integers, undefined fields omitted.
Any change to canonicalization logic breaks ALL existing signatures.
Never modify the canonical format without a version bump.

## Invariant 2: Prompt only as hash, never checked as rule

The agent's prompt/transcript is included only as `traceHash` (SHA-256).
The verifier NEVER inspects, parses, or evaluates prompt content.
This is evidence for post-hoc audit, not a runtime check.
Reason: prompts are unbounded natural language; checking them would require an LLM in the verification path, which destroys determinism and creates an oracle attack surface.

## Invariant 3: verifyOrder stays pure

`verifyOrder` is a pure function: no I/O, no network calls, no file access, no database queries.
Time comes only from the `now` parameter.
State comes only from the `state` and `nonceRegistry` parameters.
This guarantees deterministic, reproducible verification across all environments.

## Invariant 4: On-chain, out-of-scope orders never leave escrow

If the on-chain program's scope check fails, the escrow funds MUST NOT be released.
The `clear` instruction rejects out-of-scope orders.
The `settle` instruction holds funds until the dispute window passes.
`release` only works after the dispute window.
There is no admin override, no emergency release, no operator backdoor.

## Invariant 5: Liability assignment follows mandate-scope-v1

| Condition | Decision | Liability |
|---|---|---|
| Mandate signature invalid | REJECT | NONE (never debit) |
| Agent mismatch, attestation invalid, hash mismatch, replay | REJECT | AGENT_PROVIDER |
| Order outside constraints (merchant, category, amount, budget, qty, time, count) | REJECT | AGENT_PROVIDER |
| Order inside constraints, all checks pass | APPROVE | PRINCIPAL |
| Wrong goods delivered | Not in verifier scope | Merchant (downstream dispute) |

The verifier MUST check in this exact order:
1. Mandate signature (fail → NONE)
2. Attestation (signature, agent match, hash match, cart signature, replay) (fail → AGENT_PROVIDER)
3. Time window (fail → AGENT_PROVIDER)
4. Order integrity — sum, currency (fail → AGENT_PROVIDER)
5. Scope — merchant, category, SKU, quantity, item price, per-order limit, budget, order count (fail → AGENT_PROVIDER)

Early return on mandate signature failure ensures we never debit on a forged mandate.
