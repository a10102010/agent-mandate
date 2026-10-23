/**
 * Pure verifier function.
 * No I/O, no side effects. Time only via `now` parameter.
 *
 * Verification order:
 * 1. Mandate signature
 * 2. Attestation (signature, agent match, hash match, merchant cart signature, replay)
 * 3. Time window
 * 4. Order integrity (sum, currency)
 * 5. Scope (merchant, category, sku, quantity, item price, per-order limit, budget, order count)
 */

import { canonicalize, hashCanonicalHex } from './canonical.js';
import {
  verifyEd25519,
  pubkeyFromBase58,
  signatureFromBase58,
  type Scheme,
} from './crypto.js';
import type { NonceRegistry } from './nonce.js';
import type {
  SignedMandate,
  SignedOrder,
  SignedAttestation,
  Order,
  VerifierState,
  VerifyResult,
  Violation,
  Decision,
  Liability,
} from './types.js';

export interface VerifyOrderInput {
  signedMandate: SignedMandate;
  order: SignedOrder;
  signedAttestation: SignedAttestation;
  state: VerifierState;
  nonceRegistry: NonceRegistry;
  now: number; // unix seconds
}

/**
 * Pure verification function. Synchronous (ed25519 only in the verifier path).
 * For es256, use verifyOrderAsync.
 */
export function verifyOrder(input: VerifyOrderInput): VerifyResult {
  const { signedMandate, order, signedAttestation, state, nonceRegistry, now } = input;
  const violations: Violation[] = [];
  const mandate = signedMandate.mandate;
  const attestation = signedAttestation.attestation;

  const mandateHash = hashCanonicalHex(mandate);
  const plainOrder: Order = {
    orderId: order.orderId,
    merchant: order.merchant,
    currency: order.currency,
    items: order.items,
    total: order.total,
    createdAt: order.createdAt,
  };
  const orderHash = hashCanonicalHex(plainOrder);
  const attestationHash = hashCanonicalHex(attestation);

  // ── 1. Mandate signature ──
  {
    const canonical = canonicalize(mandate);
    const messageBytes = new TextEncoder().encode(canonical);
    const sigBytes = signatureFromBase58(signedMandate.signature);
    const pubBytes = pubkeyFromBase58(mandate.principal.pubkey);

    let valid = false;
    if (mandate.principal.scheme === 'ed25519') {
      valid = verifyEd25519(messageBytes, sigBytes, pubBytes);
    }
    // For es256 in a pure sync path, we cannot verify — use verifyOrderAsync

    if (!valid) {
      violations.push({ code: 'MANDATE_SIG_INVALID', detail: 'Mandate signature verification failed' });
      return makeResult('REJECT', 'NONE', violations, mandateHash, orderHash, attestationHash, mandate.constraints.maxTotal - state.spent);
    }
  }

  // ── 2. Attestation ──
  // 2a. Attestation signature
  {
    const canonical = canonicalize(attestation);
    const messageBytes = new TextEncoder().encode(canonical);
    const sigBytes = signatureFromBase58(signedAttestation.signature);
    const pubBytes = pubkeyFromBase58(attestation.agentPubkey);

    let valid = false;
    if (pubBytes.length === 32) {
      valid = verifyEd25519(messageBytes, sigBytes, pubBytes);
    }

    if (!valid) {
      violations.push({ code: 'ATTESTATION_SIG_INVALID', detail: 'Attestation signature verification failed' });
    }
  }

  // 2b. Agent match
  if (attestation.agentId !== mandate.agent.id || attestation.agentPubkey !== mandate.agent.pubkey) {
    violations.push({
      code: 'ATTESTATION_AGENT_MISMATCH',
      detail: `Agent in attestation (${attestation.agentId}) does not match mandate agent (${mandate.agent.id})`,
    });
  }

  // 2c. Hash match
  if (attestation.mandateHash !== mandateHash) {
    violations.push({
      code: 'ATTESTATION_HASH_MISMATCH',
      detail: 'Attestation mandateHash does not match computed mandate hash',
    });
  }
  if (attestation.orderHash !== orderHash) {
    violations.push({
      code: 'ATTESTATION_HASH_MISMATCH',
      detail: 'Attestation orderHash does not match computed order hash',
    });
  }

  // 2d. Merchant cart signature
  {
    const canonical = canonicalize(plainOrder);
    const messageBytes = new TextEncoder().encode(canonical);
    const sigBytes = signatureFromBase58(order.cartSignature);
    const pubBytes = pubkeyFromBase58(order.merchantPubkey);

    let valid = false;
    if (pubBytes.length === 32) {
      valid = verifyEd25519(messageBytes, sigBytes, pubBytes);
    }

    if (!valid) {
      violations.push({ code: 'CART_SIG_INVALID', detail: 'Merchant cart signature verification failed' });
    }
  }

  // 2e. Replay check
  if (nonceRegistry.has(attestationHash)) {
    violations.push({ code: 'ATTESTATION_REPLAYED', detail: 'This attestation has already been processed' });
  }

  // If any attestation violations, reject with AGENT_PROVIDER liability
  if (violations.length > 0) {
    return makeResult('REJECT', 'AGENT_PROVIDER', violations, mandateHash, orderHash, attestationHash, mandate.constraints.maxTotal - state.spent);
  }

  // ── 3. Time window ──
  if (now < mandate.validFrom) {
    violations.push({ code: 'MANDATE_NOT_YET_VALID', detail: `Mandate not valid until ${mandate.validFrom}, now is ${now}` });
  }
  if (now > mandate.validUntil) {
    violations.push({ code: 'MANDATE_EXPIRED', detail: `Mandate expired at ${mandate.validUntil}, now is ${now}` });
  }

  // ── 4. Order integrity ──
  {
    const computedTotal = order.items.reduce((sum, item) => sum + item.unitPrice * item.qty, 0);
    if (computedTotal !== order.total) {
      violations.push({
        code: 'ORDER_TOTAL_MISMATCH',
        detail: `Computed total ${computedTotal} does not match declared total ${order.total}`,
      });
    }
  }

  if (order.currency !== mandate.constraints.currency) {
    violations.push({
      code: 'CURRENCY_MISMATCH',
      detail: `Order currency ${order.currency} does not match mandate currency ${mandate.constraints.currency}`,
    });
  }

  // ── 5. Scope ──
  const c = mandate.constraints;

  // Merchant allowlist
  if (c.merchants && c.merchants.length > 0) {
    if (!c.merchants.includes(order.merchant)) {
      violations.push({
        code: 'MERCHANT_NOT_ALLOWED',
        detail: `Merchant "${order.merchant}" not in allowlist`,
      });
    }
  }

  // Per-item checks
  for (const item of order.items) {
    // Category allowlist
    if (c.categories && c.categories.length > 0) {
      if (!c.categories.includes(item.category)) {
        violations.push({
          code: 'CATEGORY_NOT_ALLOWED',
          detail: `Category "${item.category}" not in allowlist`,
        });
      }
    }

    // SKU allowlist
    if (c.skus && c.skus.length > 0) {
      if (!c.skus.includes(item.sku)) {
        violations.push({
          code: 'SKU_NOT_ALLOWED',
          detail: `SKU "${item.sku}" not in allowlist`,
        });
      }
    }

    // Quantity limit
    if (c.maxQuantity !== undefined && item.qty > c.maxQuantity) {
      violations.push({
        code: 'QTY_EXCEEDED',
        detail: `Item "${item.sku}" qty ${item.qty} exceeds max ${c.maxQuantity}`,
      });
    }

    // Item price limit
    if (c.maxPerItem !== undefined && item.unitPrice > c.maxPerItem) {
      violations.push({
        code: 'ITEM_PRICE_EXCEEDED',
        detail: `Item "${item.sku}" price ${item.unitPrice} exceeds max ${c.maxPerItem}`,
      });
    }
  }

  // Per-order limit
  if (c.maxPerOrder !== undefined && order.total > c.maxPerOrder) {
    violations.push({
      code: 'ORDER_LIMIT_EXCEEDED',
      detail: `Order total ${order.total} exceeds per-order limit ${c.maxPerOrder}`,
    });
  }

  // Budget
  if (state.spent + order.total > c.maxTotal) {
    violations.push({
      code: 'BUDGET_EXCEEDED',
      detail: `Spent ${state.spent} + order ${order.total} = ${state.spent + order.total} exceeds budget ${c.maxTotal}`,
    });
  }

  // Order count
  if (c.maxOrders !== undefined && state.orders + 1 > c.maxOrders) {
    violations.push({
      code: 'ORDER_COUNT_EXCEEDED',
      detail: `Order count ${state.orders + 1} exceeds max ${c.maxOrders}`,
    });
  }

  if (violations.length > 0) {
    return makeResult('REJECT', 'AGENT_PROVIDER', violations, mandateHash, orderHash, attestationHash, mandate.constraints.maxTotal - state.spent);
  }

  // ── APPROVE ──
  // Register attestation hash for replay protection
  nonceRegistry.add(attestationHash);

  const remainingBudget = c.maxTotal - state.spent - order.total;

  return makeResult('APPROVE', 'PRINCIPAL', [], mandateHash, orderHash, attestationHash, remainingBudget);
}

function makeResult(
  decision: Decision,
  liability: Liability,
  violations: Violation[],
  mandateHash: string,
  orderHash: string,
  attestationHash: string,
  remainingBudget: number,
): VerifyResult {
  return {
    decision,
    liability,
    violations,
    mandateHash,
    orderHash,
    attestationHash,
    remainingBudget,
  };
}
