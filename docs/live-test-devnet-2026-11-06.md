# Fivefield Protocol — Devnet Live Test Evidence

**Date:** 2026-11-06
**Cluster:** Solana Devnet
**Program ID:** `EKRPj4JfLPuBWuqVmC1bA3S4Z7PdR4gAzdqUk36Xt1zV`
**tUSDC Mint:** `ECoy3RJja5kkpDpA7Ue6mLzVsAovxhWKP5AiBW5fKh9g`

---

## Participants

| Role | Pubkey |
|---|---|
| Principal | `Hpcf1Ev88fRW2SvNzZBGoSw42W3DxYM9x7nchocCEhdt` |
| Agent (agt1) | `71eFCYS49TxDQmtzUV2mpMgj5s8PpsCF2CXprZsTSJ3E` |
| Merchant | `HS2PFef9ortmAPRViCPMHQkhaFQsmcCt1YSYfCz8j3nB` |

All keys are Ed25519.

---

## Run 1 — `lt80719d`

**Mandate file:** `apps/live-test/mandate-lt80719d.json`

| Field | Value |
|---|---|
| Mandate ID | `lt80719d` |
| Nonce | `80719d4fc9f71a047578a9cc0041d344` |
| Valid until | `1794589911` |
| Max total | 10,000,000 (micro-USD) |
| Max per order | 5,000,000 (micro-USD) |
| Categories | `api_credits` |
| Merchants | `north7.ai` |
| Liability model | `mandate-scope-v1` |
| Dispute window | 60 seconds |

**Mandate hash:** `3920d853bbc690c66c148244ff10d060c966e5875062f84c11fa153539b4b29a`

**Mandate signature (base64):** `GV9EIQSJLw/q22K9NG9o30M0NuVzXF3xvildqL6H2ZY7/UwaqwZxU9UhYdv6+d+RfALoevA358+hjrJQ+FJXCw==`

### PDAs

| PDA | Address |
|---|---|
| Mandate PDA | `EJsFzCmSy6Yc7G2bhEhrhHE7ATq4oQ72BU7szAKEcvT4` |
| Verdict PDA | `Hmc7Vbp8MUM7J1uzWzDshER69Z8K1asfWfPT3FzcuTwP` |

### Transactions

| Instruction | TX Signature | Explorer |
|---|---|---|
| create_mandate | `5QNh36qFbfmYja8SN6rXVgj48txdW5qincoZ7H24AbZkDJYshJ3cjyn4HQLRrAW6vPmcitgSy7BCF5nQSp5dJLfY` | [View](https://explorer.solana.com/tx/5QNh36qFbfmYja8SN6rXVgj48txdW5qincoZ7H24AbZkDJYshJ3cjyn4HQLRrAW6vPmcitgSy7BCF5nQSp5dJLfY?cluster=devnet) |
| clear | `4UPt3LisTPZ3KyBV1S7RBG3j1QqXJjwoHPdESVCmuKPVKv2DkJHNbF3Kw3cMMKdsvmeWEmAVQbRNTejGQNPK1fqm` | [View](https://explorer.solana.com/tx/4UPt3LisTPZ3KyBV1S7RBG3j1QqXJjwoHPdESVCmuKPVKv2DkJHNbF3Kw3cMMKdsvmeWEmAVQbRNTejGQNPK1fqm?cluster=devnet) |
| settle | `2i98K77HE1ixdH2CwTHKbJM6GWpCctvshLCypeXvjAMAjwyqFVrum4hvkSQQoibdBA8ffbtqWBHJhYUvw4pZsx2i` | [View](https://explorer.solana.com/tx/2i98K77HE1ixdH2CwTHKbJM6GWpCctvshLCypeXvjAMAjwyqFVrum4hvkSQQoibdBA8ffbtqWBHJhYUvw4pZsx2i?cluster=devnet) |

---

## Run 2 — `lt95f795`

**Mandate file:** `apps/live-test/mandate-lt95f795.json`

| Field | Value |
|---|---|
| Mandate ID | `lt95f795` |
| Nonce | `95f795cc4d97213157f98b30e59e7024` |
| Valid until | `1794589986` |
| Max total | 10,000,000 (micro-USD) |
| Max per order | 5,000,000 (micro-USD) |
| Categories | `api_credits` |
| Merchants | `north7.ai` |
| Liability model | `mandate-scope-v1` |
| Dispute window | 60 seconds |

**Mandate hash:** `1efc8020805222c0c0802749507905a4c3c1e15a7e836c8d001e319d92857b26`

**Mandate signature (base64):** `nK4xhrBhIVWkIzH+fT3hBIJKJoRZyiI+sBiN2Qg6JqACYgYsuNwRpwXyytClPGbyPAEnG9BGfWjjMa9MtMLJBg==`

TX signatures available in run output.

---

## Run 3 — `lt3e317a`

**Mandate file:** `apps/live-test/mandate-lt3e317a.json`

| Field | Value |
|---|---|
| Mandate ID | `lt3e317a` |
| Nonce | `3e317a143f2e03ff03c1db723466c4f7` |
| Valid until | `1794589999` |
| Max total | 10,000,000 (micro-USD) |
| Max per order | 5,000,000 (micro-USD) |
| Categories | `api_credits` |
| Merchants | `north7.ai` |
| Liability model | `mandate-scope-v1` |
| Dispute window | 60 seconds |

**Mandate hash:** `b9159022f440a2759f0e2c4cdf78b9fb3e16ee81aeac35d234bc88b70fe6a1cb`

**Mandate signature (base64):** `bfyUfHh2PBOPP0ezSVmFosjcpqGbAiXtHVu2+vua2EWUIdJSXVXxaBeHmEdOtFRD1rbnuNzyw8u/3zjyr3N8BA==`

TX signatures available in run output.

---

## Verification

All mandate signatures can be verified against the principal pubkey `Hpcf1Ev88fRW2SvNzZBGoSw42W3DxYM9x7nchocCEhdt` using Ed25519.

The signature input is the canonical JSON (keys recursively sorted, no whitespace) of the `mandate` object. The SHA-256 hash of this canonical form must equal `mandateHash`.

Run `scripts/verify-evidence.ts` to verify signatures and check on-chain PDAs.

---

## Mainnet Cost Estimate

Based on actual Devnet spend:

| Item | Estimated Cost | Notes |
|---|---|---|
| Program deploy | ~2 SOL | 335KB binary + extend buffer rent |
| Principal wallet | 0.1 SOL + 10 USDC | SOL for TX fees, USDC for escrow |
| Agent wallet | 0.05 SOL | PDA rent-exemption + TX fees |
| Per run (create + clear + settle) | ~0.01 SOL | 3 transactions |

**Actual Devnet spend:**

| Item | SOL |
|---|---|
| Deploy (program + buffer) | 1.76 SOL |
| Principal funding | 0.05 SOL |
| Agent (3 runs total) | ~0.01 SOL |

**Upgrade authority:** `deploy-devnet.json` (no audit yet, may need fixes before mainnet).

Mainnet deploy requires ~2 SOL (higher rent-exemption threshold) plus USDC for escrow funding. The principal needs real USDC; the agent only needs SOL for transaction fees and PDA rent.
