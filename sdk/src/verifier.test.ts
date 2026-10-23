import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateEd25519KeyPair, type KeyPair } from './crypto.js';
import { issueMandate, signCart, attestOrder } from './mandate.js';
import { verifyOrder } from './verifier.js';
import { InMemoryNonceRegistry, type NonceRegistry } from './nonce.js';
import { hashCanonicalHex, canonicalize } from './canonical.js';
import { signatureToBase58, signEd25519 } from './crypto.js';
import type { Mandate, Order, SignedMandate, SignedOrder, SignedAttestation, VerifierState } from './types.js';

// ── Helpers ──

let principalKp: KeyPair;
let agentKp: KeyPair;
let merchantKp: KeyPair;
let now: number;
let nonceRegistry: NonceRegistry;
let state: VerifierState;

function setup() {
  principalKp = generateEd25519KeyPair();
  agentKp = generateEd25519KeyPair();
  merchantKp = generateEd25519KeyPair();
  now = 1700000000;
  nonceRegistry = new InMemoryNonceRegistry();
  state = { spent: 0, orders: 0 };
}

function defaultMandateData(): Omit<Mandate, 'version' | 'nonce'> {
  return {
    mandateId: 'test-mandate-001',
    principal: { scheme: 'ed25519', pubkey: principalKp.pubkey },
    agent: { id: 'test-agent', scheme: 'ed25519', pubkey: agentKp.pubkey },
    constraints: {
      currency: 'EUR',
      maxTotal: 100000,
      maxPerOrder: 50000,
      maxPerItem: 10000,
      maxQuantity: 10,
      maxOrders: 5,
      categories: ['books', 'electronics'],
      merchants: ['shop-A'],
    },
    validFrom: now - 3600,
    validUntil: now + 86400,
    policy: { liabilityModel: 'mandate-scope-v1', disputeWindowSec: 604800 },
  };
}

function defaultOrder(): Order {
  return {
    orderId: 'order-001',
    merchant: 'shop-A',
    currency: 'EUR',
    items: [{ sku: 'ITEM-1', category: 'books', unitPrice: 1500, qty: 2 }],
    total: 3000,
    createdAt: now,
  };
}

async function fullSetup(
  mandateOverrides?: Partial<Omit<Mandate, 'version' | 'nonce'>>,
  orderOverrides?: Partial<Order>,
) {
  const mandateData = { ...defaultMandateData(), ...mandateOverrides };
  const signedMandate = await issueMandate({ mandate: mandateData, principalKeyPair: principalKp });
  const order = { ...defaultOrder(), ...orderOverrides };
  const signedOrder = await signCart(order, merchantKp);
  const traceHash = hashCanonicalHex({ trace: 'test' });
  const signedAttestation = await attestOrder({
    agentKeyPair: agentKp,
    agentId: 'test-agent',
    modelVersion: 'test-v1',
    mandateHash: signedMandate.mandateHash,
    order,
    traceHash,
    timestamp: now,
  });

  return { signedMandate, signedOrder, signedAttestation, order };
}

// ── Tests ──

describe('verifier: APPROVE (happy path)', () => {
  beforeEach(setup);

  it('approves a valid order', async () => {
    const { signedMandate, signedOrder, signedAttestation } = await fullSetup();
    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'APPROVE');
    assert.equal(result.liability, 'PRINCIPAL');
    assert.equal(result.violations.length, 0);
    assert.equal(result.remainingBudget, 100000 - 3000);
  });

  it('approves when constraints have no optional limits', async () => {
    const mandateData = defaultMandateData();
    delete (mandateData.constraints as Record<string, unknown>).maxPerOrder;
    delete (mandateData.constraints as Record<string, unknown>).maxPerItem;
    delete (mandateData.constraints as Record<string, unknown>).maxQuantity;
    delete (mandateData.constraints as Record<string, unknown>).maxOrders;
    delete (mandateData.constraints as Record<string, unknown>).categories;
    delete (mandateData.constraints as Record<string, unknown>).merchants;
    delete (mandateData.constraints as Record<string, unknown>).skus;

    const signedMandate = await issueMandate({ mandate: mandateData, principalKeyPair: principalKp });
    const order = defaultOrder();
    // Change merchant to anything since no allowlist
    order.merchant = 'any-shop';
    order.items[0].category = 'anything';
    const signedOrder = await signCart(order, merchantKp);
    const traceHash = hashCanonicalHex({ trace: 'test' });
    const signedAttestation = await attestOrder({
      agentKeyPair: agentKp,
      agentId: 'test-agent',
      modelVersion: 'test-v1',
      mandateHash: signedMandate.mandateHash,
      order,
      traceHash,
      timestamp: now,
    });

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'APPROVE');
    assert.equal(result.liability, 'PRINCIPAL');
  });
});

describe('verifier: MANDATE_SIG_INVALID → NONE liability', () => {
  beforeEach(setup);

  it('rejects when mandate signature is invalid', async () => {
    const { signedMandate, signedOrder, signedAttestation } = await fullSetup();

    // Tamper with mandate signature
    const fakeKp = generateEd25519KeyPair();
    const fakeSig = signEd25519(new TextEncoder().encode('wrong'), fakeKp.secretKey);
    signedMandate.signature = signatureToBase58(fakeSig);

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    assert.equal(result.liability, 'NONE');
    assert.ok(result.violations.some(v => v.code === 'MANDATE_SIG_INVALID'));
  });
});

describe('verifier: attestation violations → AGENT_PROVIDER liability', () => {
  beforeEach(setup);

  it('rejects when attestation signature is invalid', async () => {
    const { signedMandate, signedOrder, signedAttestation } = await fullSetup();

    // Tamper with attestation signature
    const fakeSig = signEd25519(new TextEncoder().encode('wrong'), agentKp.secretKey);
    signedAttestation.signature = signatureToBase58(fakeSig);

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    assert.equal(result.liability, 'AGENT_PROVIDER');
    assert.ok(result.violations.some(v => v.code === 'ATTESTATION_SIG_INVALID'));
  });

  it('rejects when agent does not match mandate', async () => {
    const { signedMandate, signedOrder } = await fullSetup();

    // Create attestation with a different agent
    const rogue = generateEd25519KeyPair();
    const order = defaultOrder();
    const traceHash = hashCanonicalHex({ trace: 'test' });
    const signedAttestation = await attestOrder({
      agentKeyPair: rogue,
      agentId: 'rogue-agent',
      modelVersion: 'test-v1',
      mandateHash: signedMandate.mandateHash,
      order,
      traceHash,
      timestamp: now,
    });

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    assert.equal(result.liability, 'AGENT_PROVIDER');
    assert.ok(result.violations.some(v => v.code === 'ATTESTATION_AGENT_MISMATCH'));
  });

  it('rejects when attestation mandate hash does not match', async () => {
    const { signedMandate, signedOrder } = await fullSetup();

    const order = defaultOrder();
    const traceHash = hashCanonicalHex({ trace: 'test' });
    const signedAttestation = await attestOrder({
      agentKeyPair: agentKp,
      agentId: 'test-agent',
      modelVersion: 'test-v1',
      mandateHash: 'deadbeef'.repeat(8), // wrong hash
      order,
      traceHash,
      timestamp: now,
    });

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    assert.equal(result.liability, 'AGENT_PROVIDER');
    assert.ok(result.violations.some(v => v.code === 'ATTESTATION_HASH_MISMATCH'));
  });

  it('rejects when cart signature is invalid', async () => {
    const { signedMandate, signedOrder, signedAttestation } = await fullSetup();

    // Tamper with cart signature
    const fakeSig = signEd25519(new TextEncoder().encode('wrong'), merchantKp.secretKey);
    signedOrder.cartSignature = signatureToBase58(fakeSig);

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    assert.equal(result.liability, 'AGENT_PROVIDER');
    assert.ok(result.violations.some(v => v.code === 'CART_SIG_INVALID'));
  });

  it('rejects replay (same attestation submitted twice)', async () => {
    const { signedMandate, signedOrder, signedAttestation } = await fullSetup();

    // First call: approve
    const result1 = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation,
      state,
      nonceRegistry,
      now,
    });
    assert.equal(result1.decision, 'APPROVE');

    // Second call: replay detected
    const result2 = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation,
      state: { spent: 3000, orders: 1 },
      nonceRegistry,
      now,
    });

    assert.equal(result2.decision, 'REJECT');
    assert.equal(result2.liability, 'AGENT_PROVIDER');
    assert.ok(result2.violations.some(v => v.code === 'ATTESTATION_REPLAYED'));
  });
});

describe('verifier: time window violations → AGENT_PROVIDER liability', () => {
  beforeEach(setup);

  it('rejects when mandate is not yet valid', async () => {
    const { signedMandate, signedOrder, signedAttestation } = await fullSetup();

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation,
      state,
      nonceRegistry,
      now: now - 7200, // before validFrom
    });

    assert.equal(result.decision, 'REJECT');
    assert.equal(result.liability, 'AGENT_PROVIDER');
    assert.ok(result.violations.some(v => v.code === 'MANDATE_NOT_YET_VALID'));
  });

  it('rejects when mandate has expired', async () => {
    const { signedMandate, signedOrder, signedAttestation } = await fullSetup();

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation,
      state,
      nonceRegistry,
      now: now + 200000, // after validUntil
    });

    assert.equal(result.decision, 'REJECT');
    assert.equal(result.liability, 'AGENT_PROVIDER');
    assert.ok(result.violations.some(v => v.code === 'MANDATE_EXPIRED'));
  });
});

describe('verifier: order integrity violations → AGENT_PROVIDER liability', () => {
  beforeEach(setup);

  it('rejects when order total does not match sum', async () => {
    const order: Order = {
      orderId: 'order-bad-total',
      merchant: 'shop-A',
      currency: 'EUR',
      items: [{ sku: 'ITEM-1', category: 'books', unitPrice: 1500, qty: 2 }],
      total: 9999, // wrong: should be 3000
      createdAt: now,
    };

    const signedMandate = await issueMandate({ mandate: defaultMandateData(), principalKeyPair: principalKp });
    const signedOrder = await signCart(order, merchantKp);
    const traceHash = hashCanonicalHex({ trace: 'test' });
    const signedAttestation = await attestOrder({
      agentKeyPair: agentKp,
      agentId: 'test-agent',
      modelVersion: 'test-v1',
      mandateHash: signedMandate.mandateHash,
      order,
      traceHash,
      timestamp: now,
    });

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    assert.ok(result.violations.some(v => v.code === 'ORDER_TOTAL_MISMATCH'));
  });

  it('rejects currency mismatch', async () => {
    const { signedMandate, signedAttestation } = await fullSetup();

    const usdOrder: Order = {
      orderId: 'order-usd',
      merchant: 'shop-A',
      currency: 'USD',
      items: [{ sku: 'ITEM-1', category: 'books', unitPrice: 1500, qty: 2 }],
      total: 3000,
      createdAt: now,
    };
    const signedUsdOrder = await signCart(usdOrder, merchantKp);

    // We need a new attestation matching this order
    const traceHash = hashCanonicalHex({ trace: 'test' });
    const att = await attestOrder({
      agentKeyPair: agentKp,
      agentId: 'test-agent',
      modelVersion: 'test-v1',
      mandateHash: signedMandate.mandateHash,
      order: usdOrder,
      traceHash,
      timestamp: now,
    });

    const result = verifyOrder({
      signedMandate,
      order: signedUsdOrder,
      signedAttestation: att,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    assert.ok(result.violations.some(v => v.code === 'CURRENCY_MISMATCH'));
  });
});

describe('verifier: scope violations → AGENT_PROVIDER liability', () => {
  beforeEach(setup);

  it('rejects merchant not in allowlist', async () => {
    const { signedMandate } = await fullSetup();

    const order: Order = {
      orderId: 'order-bad-merchant',
      merchant: 'shop-B', // not in allowlist
      currency: 'EUR',
      items: [{ sku: 'ITEM-1', category: 'books', unitPrice: 1500, qty: 2 }],
      total: 3000,
      createdAt: now,
    };
    const signedOrder = await signCart(order, merchantKp);
    const traceHash = hashCanonicalHex({ trace: 'test' });
    const att = await attestOrder({
      agentKeyPair: agentKp,
      agentId: 'test-agent',
      modelVersion: 'test-v1',
      mandateHash: signedMandate.mandateHash,
      order,
      traceHash,
      timestamp: now,
    });

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation: att,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    assert.equal(result.liability, 'AGENT_PROVIDER');
    assert.ok(result.violations.some(v => v.code === 'MERCHANT_NOT_ALLOWED'));
  });

  it('rejects category not in allowlist', async () => {
    const { signedMandate } = await fullSetup();

    const order: Order = {
      orderId: 'order-bad-cat',
      merchant: 'shop-A',
      currency: 'EUR',
      items: [{ sku: 'ITEM-1', category: 'weapons', unitPrice: 1500, qty: 1 }],
      total: 1500,
      createdAt: now,
    };
    const signedOrder = await signCart(order, merchantKp);
    const traceHash = hashCanonicalHex({ trace: 'test' });
    const att = await attestOrder({
      agentKeyPair: agentKp,
      agentId: 'test-agent',
      modelVersion: 'test-v1',
      mandateHash: signedMandate.mandateHash,
      order,
      traceHash,
      timestamp: now,
    });

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation: att,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    assert.ok(result.violations.some(v => v.code === 'CATEGORY_NOT_ALLOWED'));
  });

  it('rejects SKU not in allowlist', async () => {
    const mandateData = {
      ...defaultMandateData(),
      constraints: {
        ...defaultMandateData().constraints,
        skus: ['ITEM-ALLOWED'],
      },
    };
    const signedMandate = await issueMandate({ mandate: mandateData, principalKeyPair: principalKp });

    const order: Order = {
      orderId: 'order-bad-sku',
      merchant: 'shop-A',
      currency: 'EUR',
      items: [{ sku: 'ITEM-FORBIDDEN', category: 'books', unitPrice: 1500, qty: 1 }],
      total: 1500,
      createdAt: now,
    };
    const signedOrder = await signCart(order, merchantKp);
    const traceHash = hashCanonicalHex({ trace: 'test' });
    const att = await attestOrder({
      agentKeyPair: agentKp,
      agentId: 'test-agent',
      modelVersion: 'test-v1',
      mandateHash: signedMandate.mandateHash,
      order,
      traceHash,
      timestamp: now,
    });

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation: att,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    assert.ok(result.violations.some(v => v.code === 'SKU_NOT_ALLOWED'));
  });

  it('rejects quantity exceeded', async () => {
    const { signedMandate } = await fullSetup();

    const order: Order = {
      orderId: 'order-too-many',
      merchant: 'shop-A',
      currency: 'EUR',
      items: [{ sku: 'ITEM-1', category: 'books', unitPrice: 100, qty: 50 }], // maxQuantity is 10
      total: 5000,
      createdAt: now,
    };
    const signedOrder = await signCart(order, merchantKp);
    const traceHash = hashCanonicalHex({ trace: 'test' });
    const att = await attestOrder({
      agentKeyPair: agentKp,
      agentId: 'test-agent',
      modelVersion: 'test-v1',
      mandateHash: signedMandate.mandateHash,
      order,
      traceHash,
      timestamp: now,
    });

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation: att,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    assert.ok(result.violations.some(v => v.code === 'QTY_EXCEEDED'));
  });

  it('rejects item price exceeded', async () => {
    const { signedMandate } = await fullSetup();

    const order: Order = {
      orderId: 'order-expensive',
      merchant: 'shop-A',
      currency: 'EUR',
      items: [{ sku: 'ITEM-1', category: 'electronics', unitPrice: 20000, qty: 1 }], // maxPerItem is 10000
      total: 20000,
      createdAt: now,
    };
    const signedOrder = await signCart(order, merchantKp);
    const traceHash = hashCanonicalHex({ trace: 'test' });
    const att = await attestOrder({
      agentKeyPair: agentKp,
      agentId: 'test-agent',
      modelVersion: 'test-v1',
      mandateHash: signedMandate.mandateHash,
      order,
      traceHash,
      timestamp: now,
    });

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation: att,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    assert.ok(result.violations.some(v => v.code === 'ITEM_PRICE_EXCEEDED'));
  });

  it('rejects per-order limit exceeded', async () => {
    const { signedMandate } = await fullSetup();

    const order: Order = {
      orderId: 'order-too-big',
      merchant: 'shop-A',
      currency: 'EUR',
      items: [{ sku: 'ITEM-1', category: 'books', unitPrice: 9000, qty: 6 }], // 54000 > maxPerOrder 50000
      total: 54000,
      createdAt: now,
    };
    const signedOrder = await signCart(order, merchantKp);
    const traceHash = hashCanonicalHex({ trace: 'test' });
    const att = await attestOrder({
      agentKeyPair: agentKp,
      agentId: 'test-agent',
      modelVersion: 'test-v1',
      mandateHash: signedMandate.mandateHash,
      order,
      traceHash,
      timestamp: now,
    });

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation: att,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    assert.ok(result.violations.some(v => v.code === 'ORDER_LIMIT_EXCEEDED'));
  });

  it('rejects budget exceeded across multiple orders', async () => {
    const { signedMandate } = await fullSetup();

    // State: already spent 98000 of 100000 budget
    const expensiveState: VerifierState = { spent: 98000, orders: 1 };

    const order: Order = {
      orderId: 'order-over-budget',
      merchant: 'shop-A',
      currency: 'EUR',
      items: [{ sku: 'ITEM-1', category: 'books', unitPrice: 5000, qty: 1 }],
      total: 5000, // 98000 + 5000 = 103000 > 100000
      createdAt: now,
    };
    const signedOrder = await signCart(order, merchantKp);
    const traceHash = hashCanonicalHex({ trace: 'test' });
    const att = await attestOrder({
      agentKeyPair: agentKp,
      agentId: 'test-agent',
      modelVersion: 'test-v1',
      mandateHash: signedMandate.mandateHash,
      order,
      traceHash,
      timestamp: now,
    });

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation: att,
      state: expensiveState,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    assert.equal(result.liability, 'AGENT_PROVIDER');
    assert.ok(result.violations.some(v => v.code === 'BUDGET_EXCEEDED'));
  });

  it('rejects order count exceeded', async () => {
    const { signedMandate } = await fullSetup();

    // State: already placed 5 orders (maxOrders is 5)
    const fullState: VerifierState = { spent: 10000, orders: 5 };

    const order: Order = {
      orderId: 'order-too-many-orders',
      merchant: 'shop-A',
      currency: 'EUR',
      items: [{ sku: 'ITEM-1', category: 'books', unitPrice: 500, qty: 1 }],
      total: 500,
      createdAt: now,
    };
    const signedOrder = await signCart(order, merchantKp);
    const traceHash = hashCanonicalHex({ trace: 'test' });
    const att = await attestOrder({
      agentKeyPair: agentKp,
      agentId: 'test-agent',
      modelVersion: 'test-v1',
      mandateHash: signedMandate.mandateHash,
      order,
      traceHash,
      timestamp: now,
    });

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation: att,
      state: fullState,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    assert.ok(result.violations.some(v => v.code === 'ORDER_COUNT_EXCEEDED'));
  });
});

describe('verifier: budget tracking across multiple orders', () => {
  beforeEach(setup);

  it('tracks remaining budget correctly across 3 orders', async () => {
    const signedMandate = await issueMandate({ mandate: defaultMandateData(), principalKeyPair: principalKp });

    let currentState: VerifierState = { spent: 0, orders: 0 };

    for (let i = 1; i <= 3; i++) {
      const order: Order = {
        orderId: `order-${i}`,
        merchant: 'shop-A',
        currency: 'EUR',
        items: [{ sku: 'ITEM-1', category: 'books', unitPrice: 1000, qty: 1 }],
        total: 1000,
        createdAt: now + i,
      };
      const signedOrder = await signCart(order, merchantKp);
      const traceHash = hashCanonicalHex({ trace: `test-${i}` });
      const att = await attestOrder({
        agentKeyPair: agentKp,
        agentId: 'test-agent',
        modelVersion: 'test-v1',
        mandateHash: signedMandate.mandateHash,
        order,
        traceHash,
        timestamp: now + i,
      });

      const result = verifyOrder({
        signedMandate,
        order: signedOrder,
        signedAttestation: att,
        state: currentState,
        nonceRegistry,
        now: now + i,
      });

      assert.equal(result.decision, 'APPROVE', `Order ${i} should be approved`);
      assert.equal(result.remainingBudget, 100000 - 1000 * i);

      // Update state for next iteration
      currentState = { spent: currentState.spent + 1000, orders: currentState.orders + 1 };
    }
  });
});

describe('verifier: key-order independence of canonicalization', () => {
  beforeEach(setup);

  it('mandate hash is the same regardless of key insertion order', async () => {
    // Issue mandate normally
    const { signedMandate } = await fullSetup();

    // Reconstruct mandate with shuffled keys manually
    const m = signedMandate.mandate;
    const reordered = {
      nonce: m.nonce,
      version: m.version,
      policy: { disputeWindowSec: m.policy.disputeWindowSec, liabilityModel: m.policy.liabilityModel },
      validUntil: m.validUntil,
      constraints: m.constraints,
      agent: { pubkey: m.agent.pubkey, id: m.agent.id, scheme: m.agent.scheme },
      principal: { pubkey: m.principal.pubkey, scheme: m.principal.scheme },
      mandateId: m.mandateId,
      validFrom: m.validFrom,
    };

    const hash1 = hashCanonicalHex(m);
    const hash2 = hashCanonicalHex(reordered);
    assert.equal(hash1, hash2);
  });
});

describe('verifier: cart manipulation detection', () => {
  beforeEach(setup);

  it('rejects when order items are modified after signing', async () => {
    const { signedMandate, signedOrder, signedAttestation } = await fullSetup();

    // Tamper with order items after merchant signed it
    signedOrder.items = [{ sku: 'EXPENSIVE', category: 'books', unitPrice: 50000, qty: 1 }];
    signedOrder.total = 50000;

    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation,
      state,
      nonceRegistry,
      now,
    });

    assert.equal(result.decision, 'REJECT');
    // Cart signature will be invalid because items changed
    assert.ok(result.violations.some(v =>
      v.code === 'CART_SIG_INVALID' || v.code === 'ATTESTATION_HASH_MISMATCH'
    ));
  });
});
