/**
 * Verifiable Intent (VI / Mastercard) Adapter
 *
 * Translates between VI's 3-layer SD-JWT credential chain and our
 * Mandate/Attestation/Verdict types.
 *
 * VI uses a layered SD-JWT delegation:
 *   L1 (Issuer → User identity) → L2 (User → Agent constraints) → L3 (Agent → final values)
 *
 * Our system uses:
 *   Mandate (Principal signs) → Order (Merchant signs) → Attestation (Agent signs)
 *
 * The adapter maps VI Autonomous mode (3-layer) to our system.
 * VI Immediate mode (2-layer) cannot map because it has no agent delegation.
 *
 * Signatures are preserved, not re-signed. VI chain verification happens
 * separately from our verifyOrder — the adapter is pure translation.
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
  type VerifyResult,
  hashCanonicalHex,
  pubkeyToBase58,
  canonicalize,
  sha256Hex,
} from 'agent-mandate-sdk';

// ── VI Types (from spec) ──

/** VI constraint types */
export interface VIConstraint {
  type: string;
  [key: string]: unknown;
}

export interface VIAllowedMerchantConstraint extends VIConstraint {
  type: 'mandate.checkout.allowed_merchants';
  allowed: Array<{ id: string; name: string; website?: string }>;
}

export interface VIPaymentAmountConstraint extends VIConstraint {
  type: 'mandate.payment.amount_range';
  currency: string;
  min?: number;
  max?: number;
}

export interface VIBudgetConstraint extends VIConstraint {
  type: 'mandate.payment.budget';
  currency: string;
  max: number;
  min?: number;
}

export interface VILineItemsConstraint extends VIConstraint {
  type: 'mandate.checkout.line_items';
  items: Array<{
    sku: string;
    name: string;
    quantity: number;
    acceptable_items?: Array<{ id: string; title: string }>;
  }>;
  match_mode?: string;
}

export interface VIRecurrenceConstraint extends VIConstraint {
  type: 'mandate.payment.agent_recurrence';
  frequency: string;
  max_occurrences?: number;
}

export interface VIReferenceConstraint extends VIConstraint {
  type: 'mandate.payment.reference';
  conditional_transaction_id: string;
}

/** VI Cart structure */
export interface VICartItem {
  sku: string;
  name: string;
  quantity: number;
  price: string; // decimal string e.g. "99.99"
  currency: string;
}

export interface VICart {
  merchant_name: string;
  merchant_url: string;
  items: VICartItem[];
  total: string; // decimal string
  currency: string;
}

/** Parsed VI layers */
export interface VILayer {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  disclosures: Array<{ salt: string; key?: string; value: unknown }>;
}

/**
 * Composite VI record: the full 3-layer chain plus cart.
 * This is what comes in from a VI-enabled flow.
 */
export interface VIRecord {
  l1SdJwt: string;
  l2SdJwt: string;
  l3PaymentSdJwt?: string;
  l3CheckoutSdJwt?: string;
  checkoutJwt?: string; // merchant-signed cart
  cart?: VICart;
}

/** Result of VI → our system translation */
export interface VITranslationResult {
  mandate: Mandate;
  order?: Order;
  attestationFields?: Partial<Attestation>;
  /** Original VI SD-JWTs (preserved for audit) */
  originalRecord: VIRecord;
  warnings: string[];
}

/** Our system → VI record */
export interface ToVIResult {
  /** VI-compatible constraint list for L2 autonomous mandate */
  checkoutConstraints: VIConstraint[];
  paymentConstraints: VIConstraint[];
  /** Cart in VI format */
  cart?: VICart;
  warnings: string[];
}

// ── Errors ──

export class VITranslationError extends Error {
  constructor(
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = 'VITranslationError';
  }
}

// ── SD-JWT Parsing ──

/** Parse a VI SD-JWT into header, payload, and disclosures */
export function parseVISdJwt(sdJwt: string): VILayer {
  const parts = sdJwt.split('~');
  const jwt = parts[0];
  const jwtParts = jwt.split('.');
  if (jwtParts.length !== 3) {
    throw new VITranslationError('INVALID_SD_JWT', 'VI SD-JWT must have 3 JWT parts');
  }

  const header = JSON.parse(
    Buffer.from(jwtParts[0], 'base64url').toString(),
  ) as Record<string, unknown>;
  const payload = JSON.parse(
    Buffer.from(jwtParts[1], 'base64url').toString(),
  ) as Record<string, unknown>;

  const disclosures: Array<{ salt: string; key?: string; value: unknown }> = [];
  for (let i = 1; i < parts.length; i++) {
    if (!parts[i]) continue;
    try {
      const decoded = JSON.parse(Buffer.from(parts[i], 'base64url').toString());
      if (Array.isArray(decoded)) {
        if (decoded.length === 3) {
          disclosures.push({ salt: decoded[0], key: decoded[1], value: decoded[2] });
        } else if (decoded.length === 2) {
          disclosures.push({ salt: decoded[0], value: decoded[1] });
        }
      }
    } catch {
      // KB-JWT or non-disclosure — skip
    }
  }

  return { header, payload, disclosures };
}

// ── VI → Our Mandate ──

/**
 * Translate a VI Autonomous record (L1 + L2 + L3) into our Mandate.
 *
 * L1 is used only to extract the user's public key (principal).
 * L2 contains constraints (the mandate scope).
 * L3 contains final values (the attestation equivalent).
 *
 * @throws VITranslationError on missing required fields or wrong mode
 */
export function fromVIRecord(input: {
  record: VIRecord;
  /** Agent ID (from L2 cnf.jwk.kid or external) */
  agentId: string;
  /** Dispute window in seconds (VI has no equivalent — caller provides) */
  disputeWindowSec: number;
}): VITranslationResult {
  const { record, agentId, disputeWindowSec } = input;
  const warnings: string[] = [];

  // Parse L1 to extract user (principal) pubkey
  const l1 = parseVISdJwt(record.l1SdJwt);
  const cnf = l1.payload.cnf as { jwk?: jose.JWK } | undefined;
  if (!cnf?.jwk) {
    throw new VITranslationError('MISSING_PRINCIPAL_KEY', 'VI L1 must have cnf.jwk');
  }
  const userJwk = cnf.jwk;
  if (userJwk.kty !== 'EC' || userJwk.crv !== 'P-256') {
    throw new VITranslationError(
      'UNSUPPORTED_SCHEME',
      'VI uses ES256 only; ed25519 mandates cannot be translated',
    );
  }

  const userPubkeyRaw = jwkToUncompressedPoint(userJwk);

  // Parse L2 to extract constraints and agent key
  const l2 = parseVISdJwt(record.l2SdJwt);

  // Detect mode: autonomous has open VCTs in disclosures
  const l2Vcts = new Set<string>();
  for (const disc of l2.disclosures) {
    if (typeof disc.value === 'object' && disc.value !== null) {
      const v = disc.value as Record<string, unknown>;
      if (typeof v.vct === 'string') l2Vcts.add(v.vct);
    }
  }

  const isAutonomous = [...l2Vcts].some(v => v.includes('open'));
  const isImmediate = [...l2Vcts].some(v => !v.includes('open') && v.includes('mandate'));

  if (isImmediate && !isAutonomous) {
    throw new VITranslationError(
      'WRONG_MODE',
      'VI immediate mode has no agent delegation; use autonomous mode',
    );
  }

  // Extract constraints from L2 mandate disclosures
  const constraints: Constraints = { currency: '', maxTotal: 0 };
  let agentJwk: jose.JWK | undefined;

  for (const disc of l2.disclosures) {
    if (typeof disc.value !== 'object' || disc.value === null) continue;
    const mandateDisc = disc.value as Record<string, unknown>;

    // Extract agent key from cnf in mandate disclosure
    if (mandateDisc.cnf) {
      const mcnf = mandateDisc.cnf as { jwk?: jose.JWK };
      if (mcnf.jwk) agentJwk = mcnf.jwk;
    }

    // Extract constraints
    if (Array.isArray(mandateDisc.constraints)) {
      for (const c of mandateDisc.constraints as VIConstraint[]) {
        applyVIConstraint(c, constraints, warnings);
      }
    }
  }

  // Also check top-level payload for merchants/items disclosures
  for (const disc of l2.disclosures) {
    if (typeof disc.value === 'object' && disc.value !== null) {
      const v = disc.value as Record<string, unknown>;
      // Standalone merchant disclosure
      if (v.id && v.name && !v.vct) {
        if (!constraints.merchants) constraints.merchants = [];
        constraints.merchants.push(v.id as string);
      }
    }
  }

  if (!agentJwk) {
    throw new VITranslationError(
      'MISSING_AGENT_KEY',
      'VI L2 autonomous mandate must have cnf.jwk for agent delegation',
    );
  }

  const agentPubkeyRaw = jwkToUncompressedPoint(agentJwk);

  if (!constraints.maxTotal) {
    throw new VITranslationError(
      'MISSING_REQUIRED',
      'VI mandate has no budget constraint; cannot derive maxTotal',
    );
  }

  if (!constraints.currency) {
    throw new VITranslationError(
      'MISSING_REQUIRED',
      'VI mandate has no currency in any constraint',
    );
  }

  warnings.push('FIELD_NOT_EXPRESSIBLE: VI has no category allowlist');

  const mandate: Mandate = {
    version: '1',
    mandateId: `vi-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
    principal: {
      scheme: 'es256',
      pubkey: pubkeyToBase58(userPubkeyRaw),
    },
    agent: {
      id: agentId,
      scheme: 'es256',
      pubkey: pubkeyToBase58(agentPubkeyRaw),
    },
    constraints,
    validFrom: (l2.payload.iat as number) ?? 0,
    validUntil: (l2.payload.exp as number) ?? 0,
    nonce: (l2.payload.nonce as string) ?? crypto.randomUUID().replace(/-/g, ''),
    policy: {
      liabilityModel: 'mandate-scope-v1',
      disputeWindowSec,
    },
  };

  // Translate cart if present
  let order: Order | undefined;
  if (record.cart) {
    order = fromVICart(record.cart);
  }

  // Extract L3 attestation-equivalent fields
  let attestationFields: Partial<Attestation> | undefined;
  if (record.l3PaymentSdJwt) {
    const l3 = parseVISdJwt(record.l3PaymentSdJwt);
    attestationFields = {
      agentId,
      timestamp: (l3.payload.iat as number) ?? 0,
    };
  }

  return {
    mandate,
    order,
    attestationFields,
    originalRecord: record,
    warnings,
  };
}

// ── VI Cart → Our Order ──

/** Translate a VI Cart into our Order type */
export function fromVICart(cart: VICart): Order {
  const items: OrderItem[] = cart.items.map(i => ({
    sku: i.sku,
    category: '', // VI has no category
    unitPrice: Math.round(parseFloat(i.price) * 100),
    qty: i.quantity,
  }));

  const total = items.reduce((sum, i) => sum + i.unitPrice * i.qty, 0);

  return {
    orderId: `vi-order-${Date.now()}`,
    merchant: cart.merchant_name,
    currency: cart.currency,
    items,
    total,
    createdAt: Math.floor(Date.now() / 1000),
  };
}

// ── Our System → VI ──

/**
 * Translate our Mandate + Order into VI-compatible constraint lists
 * and cart format. Does NOT produce SD-JWTs — only the payloads.
 *
 * @throws VITranslationError if mandate uses ed25519
 */
export function toVI(input: {
  mandate: Mandate;
  order?: Order;
}): ToVIResult {
  const { mandate, order } = input;
  const warnings: string[] = [];
  const c = mandate.constraints;

  if (mandate.principal.scheme === 'ed25519') {
    throw new VITranslationError(
      'UNSUPPORTED_SCHEME',
      'ed25519 not supported by VI (ES256 only)',
    );
  }

  const checkoutConstraints: VIConstraint[] = [];
  const paymentConstraints: VIConstraint[] = [];

  // Budget
  paymentConstraints.push({
    type: 'mandate.payment.budget',
    currency: c.currency,
    max: c.maxTotal,
  });

  // maxPerOrder → amount_range
  if (c.maxPerOrder !== undefined) {
    paymentConstraints.push({
      type: 'mandate.payment.amount_range',
      currency: c.currency,
      max: c.maxPerOrder,
    });
  }

  // Merchants
  if (c.merchants?.length) {
    checkoutConstraints.push({
      type: 'mandate.checkout.allowed_merchants',
      allowed: c.merchants.map(id => ({ id, name: id })),
    });
  }

  // SKUs → line_items
  if (c.skus?.length) {
    checkoutConstraints.push({
      type: 'mandate.checkout.line_items',
      items: c.skus.map(sku => ({
        sku,
        name: sku,
        quantity: c.maxQuantity ?? 999,
      })),
      match_mode: 'any',
    });
  }

  // maxOrders → recurrence
  if (c.maxOrders !== undefined) {
    paymentConstraints.push({
      type: 'mandate.payment.agent_recurrence',
      frequency: 'ON_DEMAND',
      max_occurrences: c.maxOrders,
    });
  }

  // Fields lost
  if (c.categories?.length) {
    warnings.push('FIELD_NOT_EXPRESSIBLE: categories allowlist has no equivalent in VI');
  }
  if (c.maxPerItem !== undefined) {
    warnings.push('FIELD_NOT_EXPRESSIBLE: maxPerItem has no equivalent in VI');
  }
  warnings.push('FIELD_NOT_EXPRESSIBLE: policy.liabilityModel has no equivalent in VI');
  warnings.push('FIELD_NOT_EXPRESSIBLE: policy.disputeWindowSec has no equivalent in VI');

  // Translate order to cart
  let cart: VICart | undefined;
  if (order) {
    cart = {
      merchant_name: order.merchant,
      merchant_url: '',
      items: order.items.map(i => ({
        sku: i.sku,
        name: i.sku,
        quantity: i.qty,
        price: (i.unitPrice / 100).toFixed(2),
        currency: order.currency,
      })),
      total: (order.total / 100).toFixed(2),
      currency: order.currency,
    };
  }

  return { checkoutConstraints, paymentConstraints, cart, warnings };
}

/**
 * Build a VerifyResult-compatible input from a VI record.
 * This allows feeding VI data through our verifyOrder after translation.
 * The caller must still provide signed versions — this helper produces
 * the unsigned mandate and order for re-signing in our format.
 */
export function viRecordToVerifyInput(input: {
  record: VIRecord;
  agentId: string;
  disputeWindowSec: number;
}): VITranslationResult {
  return fromVIRecord(input);
}

// ── Helpers ──

function jwkToUncompressedPoint(jwk: jose.JWK): Uint8Array {
  const x = Buffer.from(jwk.x!, 'base64url');
  const y = Buffer.from(jwk.y!, 'base64url');
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(x, 1);
  raw.set(y, 33);
  return raw;
}

function applyVIConstraint(
  c: VIConstraint,
  constraints: Constraints,
  warnings: string[],
): void {
  switch (c.type) {
    case 'mandate.payment.budget': {
      const bc = c as VIBudgetConstraint;
      constraints.maxTotal = bc.max;
      constraints.currency = bc.currency;
      break;
    }
    case 'mandate.payment.amount_range': {
      const ar = c as VIPaymentAmountConstraint;
      if (ar.max !== undefined) constraints.maxPerOrder = ar.max;
      if (!constraints.currency && ar.currency) constraints.currency = ar.currency;
      break;
    }
    case 'mandate.checkout.allowed_merchants': {
      const am = c as VIAllowedMerchantConstraint;
      constraints.merchants = am.allowed.map(m => m.id);
      break;
    }
    case 'mandate.checkout.line_items': {
      const li = c as VILineItemsConstraint;
      const skus: string[] = [];
      for (const item of li.items) {
        skus.push(item.sku);
        if (item.acceptable_items) {
          for (const ai of item.acceptable_items) {
            skus.push(ai.id);
          }
        }
      }
      if (skus.length > 0) constraints.skus = skus;
      break;
    }
    case 'mandate.payment.agent_recurrence': {
      const rc = c as VIRecurrenceConstraint;
      if (rc.max_occurrences !== undefined) {
        constraints.maxOrders = rc.max_occurrences;
      }
      break;
    }
    case 'mandate.payment.reference':
      // Internal VI binding — not a constraint in our model
      break;
    default:
      warnings.push(`UNKNOWN_CONSTRAINT: ${c.type} skipped`);
  }
}
