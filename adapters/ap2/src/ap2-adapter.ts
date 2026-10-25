/**
 * AP2 (Google Agent Payments Protocol) Adapter
 *
 * Translates between AP2 Open Mandates (SD-JWT) and our Mandate/Attestation
 * types. Adapter is pure translation — verifyOrder stays untouched.
 *
 * AP2 uses SD-JWT with ES256 signatures. Our system uses canonical JSON with
 * Ed25519 or ES256. The adapter parses AP2 SD-JWTs using `jose`, extracts
 * claims and constraints, and maps them to our Mandate structure.
 *
 * Signatures are passed through, not re-signed. The adapter stores the
 * original AP2 SD-JWT alongside the translated mandate for audit.
 */

import * as jose from 'jose';
import {
  type Mandate,
  type SignedMandate,
  type Order,
  type SignedOrder,
  type OrderItem,
  type Attestation,
  type SignedAttestation,
  type Constraints,
  hashCanonicalHex,
  pubkeyToBase58,
} from 'agent-mandate-sdk';

// ── AP2 Types (from spec) ──

export interface AP2Merchant {
  id: string;
  name: string;
  website?: string;
}

export interface AP2Amount {
  amount: number; // minor units
  currency: string; // ISO 4217
}

export interface AP2PaymentInstrument {
  id: string;
  type: string;
  description?: string;
}

export interface AP2LineItem {
  id: string;
  product: {
    id: string;
    title: string;
    price: number; // float (dollars)
    currency: string;
  };
  quantity: number;
}

export interface AP2CheckoutJwtPayload {
  order_id: string;
  merchant: AP2Merchant;
  line_items: AP2LineItem[];
  total_price: number; // float
  currency: string;
  shipping_policy?: string;
  return_policy?: string;
}

/** AP2 constraint types */
export interface AP2Constraint {
  type: string;
  [key: string]: unknown;
}

export interface AP2AmountRangeConstraint extends AP2Constraint {
  type: 'payment.amount_range';
  currency: string;
  min?: number;
  max?: number;
}

export interface AP2BudgetConstraint extends AP2Constraint {
  type: 'payment.budget';
  currency: string;
  max: number;
  min?: number;
}

export interface AP2AllowedMerchantsConstraint extends AP2Constraint {
  type: 'checkout.allowed_merchants';
  allowed: AP2Merchant[];
}

export interface AP2AllowedPayeesConstraint extends AP2Constraint {
  type: 'payment.allowed_payees';
  allowed: AP2Merchant[];
}

export interface AP2RecurrenceConstraint extends AP2Constraint {
  type: 'payment.agent_recurrence';
  frequency: string;
  max_occurrences?: number;
}

export interface AP2LineItemsConstraint extends AP2Constraint {
  type: 'checkout.line_items';
  items: Array<{
    id: string;
    quantity: number;
    acceptable_items: Array<{ id: string; title: string }>;
  }>;
}

/** Parsed AP2 Open Mandate (extracted from SD-JWT) */
export interface AP2OpenMandate {
  vct: string;
  cnf?: { jwk: jose.JWK };
  constraints: AP2Constraint[];
  iat: number;
  exp: number;
}

/** Result of translating AP2 → our system */
export interface AP2TranslationResult {
  mandate: Mandate;
  /** Original AP2 SD-JWT (preserved for audit) */
  originalCheckoutSdJwt?: string;
  originalPaymentSdJwt?: string;
  /** Fields that could not be translated */
  warnings: string[];
}

/** Result of translating our system → AP2 */
export interface ToAP2Result {
  checkoutConstraints: AP2Constraint[];
  paymentConstraints: AP2Constraint[];
  /** Fields lost in translation */
  warnings: string[];
}

// ── Translation Errors ──

export class AP2TranslationError extends Error {
  constructor(
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = 'AP2TranslationError';
  }
}

// ── SD-JWT Parsing ──

/**
 * Parse an AP2 SD-JWT and extract the visible claims + disclosed claims.
 * Uses `jose` for JWT decoding. Does NOT verify signatures — the adapter
 * preserves original signatures for downstream verification.
 */
export function parseAP2SdJwt(sdJwt: string): {
  header: jose.JWTHeaderParameters;
  payload: Record<string, unknown>;
  disclosures: Array<{ salt: string; key?: string; value: unknown }>;
} {
  const parts = sdJwt.split('~');
  const jwt = parts[0];

  // Decode JWT (without verification — we preserve the original sig)
  const jwtParts = jwt.split('.');
  if (jwtParts.length !== 3) {
    throw new AP2TranslationError('INVALID_SD_JWT', 'AP2 SD-JWT must have 3 parts');
  }

  const header = JSON.parse(
    Buffer.from(jwtParts[0], 'base64url').toString(),
  ) as jose.JWTHeaderParameters;
  const payload = JSON.parse(
    Buffer.from(jwtParts[1], 'base64url').toString(),
  ) as Record<string, unknown>;

  // Parse disclosures (parts[1..n-1], last may be KB-JWT or empty)
  const disclosures: Array<{ salt: string; key?: string; value: unknown }> = [];
  for (let i = 1; i < parts.length; i++) {
    const disc = parts[i];
    if (!disc) continue; // trailing separator or KB-JWT position
    try {
      const decoded = JSON.parse(Buffer.from(disc, 'base64url').toString());
      if (Array.isArray(decoded)) {
        if (decoded.length === 3) {
          disclosures.push({ salt: decoded[0], key: decoded[1], value: decoded[2] });
        } else if (decoded.length === 2) {
          disclosures.push({ salt: decoded[0], value: decoded[1] });
        }
      }
    } catch {
      // May be the Key Binding JWT — skip
    }
  }

  return { header, payload, disclosures };
}

/**
 * Extract constraints from an AP2 Open Mandate.
 * Resolves SD-JWT disclosures to reconstruct the full constraint list.
 */
export function extractAP2OpenMandate(sdJwt: string): AP2OpenMandate {
  const { payload, disclosures } = parseAP2SdJwt(sdJwt);

  const vct = payload.vct as string;
  if (!vct) {
    throw new AP2TranslationError('MISSING_VCT', 'AP2 mandate must have a vct field');
  }

  if (!vct.includes('open')) {
    throw new AP2TranslationError(
      'WRONG_MODE',
      `AP2 closed mandates (vct=${vct}) are final transactions, not delegations; use open mandates`,
    );
  }

  // Extract constraints — may be in payload directly or via disclosures
  let constraints: AP2Constraint[] = [];
  if (Array.isArray(payload.constraints)) {
    constraints = payload.constraints as AP2Constraint[];
  }

  // Also check disclosures for constraints
  for (const disc of disclosures) {
    if (disc.key === 'constraints' && Array.isArray(disc.value)) {
      constraints = disc.value as AP2Constraint[];
    }
  }

  return {
    vct,
    cnf: payload.cnf as { jwk: jose.JWK } | undefined,
    constraints,
    iat: (payload.iat as number) ?? 0,
    exp: (payload.exp as number) ?? 0,
  };
}

// ── AP2 → Our Mandate ──

/**
 * Translate an AP2 Open Checkout Mandate + Open Payment Mandate into our
 * Mandate type.
 *
 * Requires both checkout and payment SD-JWTs. Signatures are preserved,
 * not re-signed.
 *
 * @throws AP2TranslationError on missing required fields
 */
export function fromAP2IntentMandate(input: {
  checkoutSdJwt: string;
  paymentSdJwt: string;
  /** Agent ID (from AP2's cnf.jwk.kid or external) */
  agentId: string;
  /** Principal's ES256 public key (raw 65 bytes, uncompressed) */
  principalPubkey: Uint8Array;
  /** Dispute window in seconds (AP2 has no equivalent — caller must provide) */
  disputeWindowSec: number;
}): AP2TranslationResult {
  const checkout = extractAP2OpenMandate(input.checkoutSdJwt);
  const payment = extractAP2OpenMandate(input.paymentSdJwt);

  const warnings: string[] = [];

  // Extract agent pubkey from cnf.jwk
  const agentJwk = payment.cnf?.jwk ?? checkout.cnf?.jwk;
  if (!agentJwk) {
    throw new AP2TranslationError(
      'MISSING_AGENT_KEY',
      'AP2 open mandate must have cnf.jwk for agent key binding',
    );
  }
  if (agentJwk.kty !== 'EC' || agentJwk.crv !== 'P-256') {
    throw new AP2TranslationError(
      'UNSUPPORTED_SCHEME',
      `AP2 agent key must be EC P-256, got kty=${agentJwk.kty} crv=${agentJwk.crv}`,
    );
  }

  // Decode JWK to raw pubkey bytes (uncompressed: 0x04 || x || y)
  const x = Buffer.from(agentJwk.x!, 'base64url');
  const y = Buffer.from(agentJwk.y!, 'base64url');
  const agentPubkeyRaw = new Uint8Array(65);
  agentPubkeyRaw[0] = 0x04;
  agentPubkeyRaw.set(x, 1);
  agentPubkeyRaw.set(y, 33);

  // Build constraints from AP2 constraints
  const constraints: Constraints = {
    currency: '',
    maxTotal: 0,
  };

  let hasBudget = false;
  let hasAmountRange = false;

  for (const c of [...checkout.constraints, ...payment.constraints]) {
    switch (c.type) {
      case 'payment.budget': {
        const bc = c as AP2BudgetConstraint;
        constraints.maxTotal = bc.max;
        constraints.currency = bc.currency;
        hasBudget = true;
        break;
      }
      case 'payment.amount_range': {
        const ar = c as AP2AmountRangeConstraint;
        if (ar.max !== undefined) {
          constraints.maxPerOrder = ar.max;
        }
        if (!constraints.currency && ar.currency) {
          constraints.currency = ar.currency;
        }
        hasAmountRange = true;
        break;
      }
      case 'checkout.allowed_merchants': {
        const am = c as AP2AllowedMerchantsConstraint;
        constraints.merchants = am.allowed.map(m => m.id);
        break;
      }
      case 'payment.allowed_payees': {
        const ap = c as AP2AllowedPayeesConstraint;
        if (!constraints.merchants?.length) {
          constraints.merchants = ap.allowed.map(m => m.id);
        }
        break;
      }
      case 'checkout.line_items': {
        const li = c as AP2LineItemsConstraint;
        const skus: string[] = [];
        for (const item of li.items) {
          for (const ai of item.acceptable_items) {
            skus.push(ai.id);
          }
        }
        if (skus.length > 0) {
          constraints.skus = skus;
        }
        break;
      }
      case 'payment.agent_recurrence': {
        const rc = c as AP2RecurrenceConstraint;
        if (rc.max_occurrences !== undefined) {
          constraints.maxOrders = rc.max_occurrences;
        }
        break;
      }
      default:
        warnings.push(`UNKNOWN_CONSTRAINT: ${c.type} skipped`);
    }
  }

  if (!hasBudget) {
    // Try to derive from amount_range
    if (hasAmountRange && constraints.maxPerOrder) {
      constraints.maxTotal = constraints.maxPerOrder;
      warnings.push('DERIVED_BUDGET: maxTotal derived from payment.amount_range.max (no budget constraint)');
    } else {
      throw new AP2TranslationError(
        'MISSING_REQUIRED',
        'AP2 mandate has no payment.budget constraint; cannot derive maxTotal',
      );
    }
  }

  if (!constraints.currency) {
    throw new AP2TranslationError(
      'MISSING_REQUIRED',
      'AP2 mandate has no currency in budget or amount_range constraints',
    );
  }

  // AP2 has no category allowlist or maxPerItem
  // categories: [] means all allowed (same semantics as absence)
  // maxPerItem: undefined (omitted)
  // These are logged as warnings only if the source had other constraint types
  warnings.push('FIELD_NOT_EXPRESSIBLE: AP2 has no category allowlist (categories will be empty = all allowed)');

  const mandate: Mandate = {
    version: '1',
    mandateId: `ap2-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
    principal: {
      scheme: 'es256',
      pubkey: pubkeyToBase58(input.principalPubkey),
    },
    agent: {
      id: input.agentId,
      scheme: 'es256',
      pubkey: pubkeyToBase58(agentPubkeyRaw),
    },
    constraints,
    validFrom: payment.iat || checkout.iat,
    validUntil: payment.exp || checkout.exp,
    nonce: crypto.randomUUID().replace(/-/g, ''),
    policy: {
      liabilityModel: 'mandate-scope-v1',
      disputeWindowSec: input.disputeWindowSec,
    },
  };

  return {
    mandate,
    originalCheckoutSdJwt: input.checkoutSdJwt,
    originalPaymentSdJwt: input.paymentSdJwt,
    warnings,
  };
}

// ── AP2 Checkout JWT → Our Order ──

/**
 * Translate an AP2 Checkout JWT (merchant-signed) into our Order type.
 * Price conversion: AP2 uses floats (dollars), we use integer minor units (cents).
 */
export function fromAP2CheckoutJwt(checkoutJwt: string): {
  order: Order;
  /** The merchant's original JWT for signature passthrough */
  originalJwt: string;
  warnings: string[];
} {
  const parts = checkoutJwt.split('.');
  if (parts.length !== 3) {
    throw new AP2TranslationError('INVALID_JWT', 'Checkout JWT must have 3 parts');
  }

  const payload = JSON.parse(
    Buffer.from(parts[1], 'base64url').toString(),
  ) as AP2CheckoutJwtPayload;

  const warnings: string[] = [];

  const items: OrderItem[] = payload.line_items.map(li => ({
    sku: li.product.id,
    category: '', // AP2 has no category field
    unitPrice: Math.round(li.product.price * 100), // float dollars → integer cents
    qty: li.quantity,
  }));

  if (items.some(i => !i.category)) {
    warnings.push('FIELD_NOT_EXPRESSIBLE: AP2 has no item category; set to empty string');
  }

  const computedTotal = items.reduce((sum, i) => sum + i.unitPrice * i.qty, 0);
  const declaredTotal = Math.round(payload.total_price * 100);

  if (computedTotal !== declaredTotal) {
    warnings.push(
      `TOTAL_ROUNDING: computed ${computedTotal} vs declared ${declaredTotal} (float rounding)`,
    );
  }

  const order: Order = {
    orderId: payload.order_id,
    merchant: payload.merchant.id,
    currency: payload.currency,
    items,
    total: computedTotal,
    createdAt: Math.floor(Date.now() / 1000),
  };

  return { order, originalJwt: checkoutJwt, warnings };
}

// ── Our Mandate → AP2 ──

/**
 * Translate our Mandate constraints into AP2 constraint arrays.
 * Does NOT produce SD-JWTs — only the constraint payloads that would
 * go into AP2 Open Mandates.
 *
 * Fields that cannot be expressed in AP2 are listed in warnings.
 */
export function toAP2(mandate: Mandate): ToAP2Result {
  const warnings: string[] = [];
  const checkoutConstraints: AP2Constraint[] = [];
  const paymentConstraints: AP2Constraint[] = [];
  const c = mandate.constraints;

  if (mandate.principal.scheme === 'ed25519') {
    throw new AP2TranslationError(
      'UNSUPPORTED_SCHEME',
      'ed25519 not supported by AP2 (ES256 only)',
    );
  }

  // Budget → payment.budget
  paymentConstraints.push({
    type: 'payment.budget',
    currency: c.currency,
    max: c.maxTotal,
  });

  // maxPerOrder → payment.amount_range
  if (c.maxPerOrder !== undefined) {
    paymentConstraints.push({
      type: 'payment.amount_range',
      currency: c.currency,
      max: c.maxPerOrder,
    });
  }

  // merchants → checkout.allowed_merchants + payment.allowed_payees
  if (c.merchants?.length) {
    const merchantObjs = c.merchants.map(id => ({ id, name: id, website: '' }));
    checkoutConstraints.push({
      type: 'checkout.allowed_merchants',
      allowed: merchantObjs,
    });
    paymentConstraints.push({
      type: 'payment.allowed_payees',
      allowed: merchantObjs,
    });
  }

  // skus → checkout.line_items (flat — no per-line quantities)
  if (c.skus?.length) {
    checkoutConstraints.push({
      type: 'checkout.line_items',
      items: [{
        id: 'line_1',
        quantity: c.maxQuantity ?? 999,
        acceptable_items: c.skus.map(sku => ({ id: sku, title: sku })),
      }],
    });
  }

  // maxOrders → payment.agent_recurrence
  if (c.maxOrders !== undefined) {
    paymentConstraints.push({
      type: 'payment.agent_recurrence',
      frequency: 'ON_DEMAND',
      max_occurrences: c.maxOrders,
    });
  }

  // Fields we CANNOT express in AP2
  if (c.categories?.length) {
    warnings.push('FIELD_NOT_EXPRESSIBLE: categories allowlist has no equivalent in AP2');
  }
  if (c.maxPerItem !== undefined) {
    warnings.push('FIELD_NOT_EXPRESSIBLE: maxPerItem has no equivalent in AP2');
  }
  // Liability model and dispute window are not expressible
  warnings.push('FIELD_NOT_EXPRESSIBLE: policy.liabilityModel has no equivalent in AP2');
  warnings.push('FIELD_NOT_EXPRESSIBLE: policy.disputeWindowSec has no equivalent in AP2');

  return { checkoutConstraints, paymentConstraints, warnings };
}
