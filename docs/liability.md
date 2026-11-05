# Liability Model — How the Rule Becomes Binding

> **Disclaimer.** This document is not legal advice. It reflects our reading of existing payment regulation, scheme rules, and cryptographic primitives. Independent legal review is recommended before relying on any claim made here.

---

## The liability table is a technical rule

The Fivefield verifier assigns liability deterministically:

| Condition | Decision | Liability |
|---|---|---|
| Mandate signature invalid | REJECT | NONE (never charge) |
| Agent not authorized / Attestation invalid / Replay | REJECT | Agent provider |
| Order outside constraints (budget, merchant, category, etc.) | REJECT | Agent provider |
| Order within constraints | APPROVE | Principal |
| Goods wrong, faulty, or not delivered | — | Merchant (consumer law unchanged) |
| Order within constraints, user dislikes the choice | — | Principal; service matter with agent provider, consumer withdrawal rights unchanged |

A technical rule becomes enforceable through three routes. The first is already built into the protocol.

---

## Route 1: By signature, per transaction

### The hash chain

```
Mandate
  └─ policy.liabilityModel = "mandate-scope-v1"
  └─ canonicalize(mandate) → mandateHash (SHA-256)

Attestation
  └─ attestation.mandateHash = mandateHash   // references the mandate
  └─ agent signs canonicalize(attestation)    // Ed25519 signature
```

Every `Mandate` object contains a `policy` field with `liabilityModel: 'mandate-scope-v1'`. When the mandate is created, `canonicalize()` recursively sorts all keys and serializes to JSON. The SHA-256 hash of this canonical form becomes `mandateHash`.

When the agent acts on the mandate, it creates an `Attestation` that includes `mandateHash` as a field. The agent then signs the canonical form of the entire attestation with its Ed25519 key.

### Why the signature IS acceptance

The attestation signature constitutes acceptance of the liability rule because:

1. **The mandate hash is inside the signed payload.** The attestation contains `mandateHash`, which is the hash of the full mandate including `policy.liabilityModel = "mandate-scope-v1"`. By signing the attestation, the agent cryptographically commits to the specific mandate — and therefore to its liability model.

2. **The chain is tamper-proof.** Changing the liability model would change the mandate hash. An attestation referencing a different hash would fail verification against the original mandate.

3. **No separate contract needed.** Traditional liability allocation requires terms of service or bilateral agreements. Here, each transaction carries its own proof of acceptance. The agent provider's key signed a payload that references a mandate whose policy field specifies `mandate-scope-v1`. That is acceptance — per order, machine-verifiable, by anyone.

4. **It is per-transaction, not blanket.** Each attestation is a fresh, individually signed acceptance for one specific order under one specific mandate. There is no single point of revocation that retroactively changes liability for past transactions.

---

## Route 2: By scheme rule

Out-of-scope orders (agent exceeds the mandate) do not fit existing chargeback reason codes:

- **Not "no authorization"** — the card was legitimately used by an authorized agent acting under a signed mandate. Authorization existed; the agent exceeded its scope.
- **Not "not as described"** — the merchant delivered what was ordered. The dispute is not with the merchant but with the agent that placed the wrong order.

A dedicated reason code — **"agent exceeded signed mandate"** — with the verifier's verdict as evidence would let issuers route liability to the agent provider instead of the merchant. The verdict contains:

- The mandate (what was allowed)
- The attestation (what the agent claimed)
- The order (what actually happened)
- The violation codes (exactly which constraints were breached)
- All signatures (who signed what)

This is more structured evidence than any existing chargeback flow provides. Scheme adoption requires a new reason code and integration of the verdict into the dispute process.

---

## Route 3: By regulation

PSD2 (Article 97, Article 74) shifts liability to the consumer only after strong customer authentication (SCA) bound to a specific payee and a specific amount.

The Fivefield mandate provides exactly this binding for delegated purchases:

- **Payee binding** — `constraints.merchants` restricts which merchants the agent can pay.
- **Amount binding** — `constraints.maxTotal`, `maxPerOrder`, `maxPerItem` cap the amounts.
- **SCA** — the principal signs the mandate with their Ed25519 key (passkey-compatible). This signature is the authentication event, bound to the payee list and amount limits.

PSD3 and the Payment Services Regulation (PSR) technical standards are being written over the next two years. A working, deployed scoped mandate — already verifiable, already signing per transaction — is a candidate for recognition as an SCA-compliant delegation mechanism.

Our reading: the mandate satisfies the *intent* of SCA (authenticate, bind to payee, bind to amount) even before formal recognition. PSD3/PSR formal recognition would make it binding on all payment service providers in the EU.

---

## What a court sees

If a dispute reaches litigation, the evidence chain is:

1. **Mandate** — JSON document signed by the principal. Contains the five constraint fields, the validity window, and `policy.liabilityModel = "mandate-scope-v1"`. Signature verifiable with the principal's public key.

2. **Attestation** — JSON document signed by the agent. Contains `mandateHash` (binding it to the mandate), `orderHash`, `cartHash`, `traceHash`, and the agent's identity. Signature verifiable with the agent's public key.

3. **Order** — the actual purchase, including merchant, items, amounts. Cart signed by the merchant.

4. **Verdict** — the verifier's output: `decision` (APPROVE/REJECT), `liability` (PRINCIPAL/AGENT_PROVIDER/NONE), `violations[]` with specific codes and details.

All of these are:
- **Signed** — tamper-evident via Ed25519 signatures
- **Hashchained** — each document references the hash of its predecessor
- **Recomputable** — the verifier is a pure function; anyone can re-run it with the same inputs and get the same verdict
- **Deterministic** — no AI, no LLM, no oracle in the verification path; only cryptography and arithmetic

A court does not need to trust the protocol operator. It can independently verify every signature and re-run the verifier to confirm the verdict.

---

## What is open

### Scheme recognition
No card scheme currently has a reason code for "agent exceeded signed mandate." Creating one requires engagement with Visa and Mastercard dispute teams. The protocol provides the evidence structure; the scheme provides the routing.

### Regulatory recognition
PSD3/PSR technical standards are in drafting. Whether a cryptographic mandate qualifies as SCA delegation depends on the final text. The protocol is designed to be compatible with the most likely interpretations.

### Enforcement against agent providers outside the EU
The per-transaction signature provides evidence of acceptance regardless of jurisdiction. However, enforcing a liability claim against an agent provider incorporated outside the EU may require cross-border litigation. The cryptographic evidence (signed attestation referencing the liability model) is jurisdiction-neutral; the enforcement mechanism is not.

### Revocation
The protocol supports mandate revocation and attestation replay detection. What remains open is real-time revocation propagation across all payment rails — particularly for card transactions already in the authorization pipeline when revocation occurs.
