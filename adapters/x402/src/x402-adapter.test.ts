import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateEd25519KeyPair,
  issueMandate,
  signCart,
  attestOrder,
  hashCanonicalHex,
  type KeyPair,
  type Mandate,
  type Order,
} from 'agent-mandate-sdk';
import {
  verifyX402Payment,
  createX402PaymentRequest,
  createTestFacilitatorConfig,
  type FacilitatorConfig,
} from './x402-adapter.js';

let principalKp: KeyPair;
let agentKp: KeyPair;
let merchantKp: KeyPair;
let now: number;
let facilitatorConfig: FacilitatorConfig;

function setup() {
  principalKp = generateEd25519KeyPair();
  agentKp = generateEd25519KeyPair();
  merchantKp = generateEd25519KeyPair();
  now = 1700000000;
  facilitatorConfig = createTestFacilitatorConfig();
}

function defaultMandateData(): Omit<Mandate, 'version' | 'nonce'> {
  return {
    mandateId: 'x402-test-mandate',
    principal: { scheme: 'ed25519', pubkey: principalKp.pubkey },
    agent: { id: 'x402-agent', scheme: 'ed25519', pubkey: agentKp.pubkey },
    constraints: {
      currency: 'USD',
      maxTotal: 100000,
      maxPerOrder: 50000,
      categories: ['saas', 'api'],
      merchants: ['api-provider'],
    },
    validFrom: now - 3600,
    validUntil: now + 86400,
    policy: { liabilityModel: 'mandate-scope-v1', disputeWindowSec: 604800 },
  };
}

function defaultOrder(): Order {
  return {
    orderId: 'x402-order-001',
    merchant: 'api-provider',
    currency: 'USD',
    items: [{ sku: 'API-CALL-1000', category: 'api', unitPrice: 500, qty: 1 }],
    total: 500,
    createdAt: now,
  };
}

async function buildPaymentRequest(
  mandateOverrides?: Partial<Omit<Mandate, 'version' | 'nonce'>>,
  orderOverrides?: Partial<Order>,
) {
  const mandateData = { ...defaultMandateData(), ...mandateOverrides };
  const signedMandate = await issueMandate({ mandate: mandateData, principalKeyPair: principalKp });
  const order = { ...defaultOrder(), ...orderOverrides };
  const signedOrder = await signCart(order, merchantKp);
  const traceHash = hashCanonicalHex({ prompt: 'Buy API credits' });
  const signedAttestation = await attestOrder({
    agentKeyPair: agentKp,
    agentId: 'x402-agent',
    modelVersion: 'test-v1',
    mandateHash: signedMandate.mandateHash,
    order,
    traceHash,
    timestamp: now,
  });

  return createX402PaymentRequest(signedMandate, signedOrder, signedAttestation);
}

describe('x402 adapter: happy path', () => {
  beforeEach(setup);

  it('approves a valid x402 payment', async () => {
    const request = await buildPaymentRequest();
    const result = verifyX402Payment(request, facilitatorConfig, now);

    assert.equal(result.decision, 'APPROVE');
    assert.equal(result.liability, 'PRINCIPAL');
    assert.equal(result.proceedWithSettlement, true);
    assert.equal(result.violations.length, 0);
    assert.equal(result.remainingBudget, 100000 - 500);
  });

  it('tracks state across multiple payments', async () => {
    // First payment
    const req1 = await buildPaymentRequest();
    const result1 = verifyX402Payment(req1, facilitatorConfig, now);
    assert.equal(result1.decision, 'APPROVE');
    assert.equal(result1.remainingBudget, 99500);

    // Second payment (different order)
    const order2: Order = {
      orderId: 'x402-order-002',
      merchant: 'api-provider',
      currency: 'USD',
      items: [{ sku: 'API-CALL-1000', category: 'api', unitPrice: 2000, qty: 1 }],
      total: 2000,
      createdAt: now + 1,
    };

    const mandateData = defaultMandateData();
    const signedMandate = await issueMandate({ mandate: mandateData, principalKeyPair: principalKp });
    const signedOrder = await signCart(order2, merchantKp);
    const traceHash = hashCanonicalHex({ prompt: 'More credits' });
    const signedAttestation = await attestOrder({
      agentKeyPair: agentKp,
      agentId: 'x402-agent',
      modelVersion: 'test-v1',
      mandateHash: signedMandate.mandateHash,
      order: order2,
      traceHash,
      timestamp: now + 1,
    });

    const req2 = createX402PaymentRequest(signedMandate, signedOrder, signedAttestation);
    const result2 = verifyX402Payment(req2, facilitatorConfig, now + 1);

    assert.equal(result2.decision, 'APPROVE');
    // State should reflect first payment's spend
    assert.equal(result2.remainingBudget, 100000 - 500 - 2000);
  });
});

describe('x402 adapter: rejection cases', () => {
  beforeEach(setup);

  it('rejects expired mandate', async () => {
    const request = await buildPaymentRequest();
    const futureNow = now + 200000; // well past validUntil
    const result = verifyX402Payment(request, facilitatorConfig, futureNow);

    assert.equal(result.decision, 'REJECT');
    assert.equal(result.proceedWithSettlement, false);
    assert.ok(result.violations.some(v => v.code === 'MANDATE_EXPIRED'));
  });

  it('rejects wrong merchant', async () => {
    const request = await buildPaymentRequest(undefined, {
      merchant: 'evil-merchant',
      orderId: 'x402-evil',
    });

    // Need to rebuild with correct hashes — the adapter uses the full flow
    // Since the order has wrong merchant, it will be rejected by scope check
    const mandateData = defaultMandateData();
    const signedMandate = await issueMandate({ mandate: mandateData, principalKeyPair: principalKp });
    const badOrder: Order = {
      orderId: 'x402-evil',
      merchant: 'evil-merchant',
      currency: 'USD',
      items: [{ sku: 'API-CALL-1000', category: 'api', unitPrice: 500, qty: 1 }],
      total: 500,
      createdAt: now,
    };
    const signedOrder = await signCart(badOrder, merchantKp);
    const traceHash = hashCanonicalHex({ prompt: 'Buy from evil' });
    const signedAttestation = await attestOrder({
      agentKeyPair: agentKp,
      agentId: 'x402-agent',
      modelVersion: 'test-v1',
      mandateHash: signedMandate.mandateHash,
      order: badOrder,
      traceHash,
      timestamp: now,
    });

    const req = createX402PaymentRequest(signedMandate, signedOrder, signedAttestation);
    const result = verifyX402Payment(req, facilitatorConfig, now);

    assert.equal(result.decision, 'REJECT');
    assert.equal(result.proceedWithSettlement, false);
    assert.equal(result.liability, 'AGENT_PROVIDER');
    assert.ok(result.violations.some(v => v.code === 'MERCHANT_NOT_ALLOWED'));
  });

  it('rejects replay of same payment', async () => {
    const request = await buildPaymentRequest();

    // First: approve
    const result1 = verifyX402Payment(request, facilitatorConfig, now);
    assert.equal(result1.decision, 'APPROVE');

    // Second: replay rejected
    const result2 = verifyX402Payment(request, facilitatorConfig, now);
    assert.equal(result2.decision, 'REJECT');
    assert.equal(result2.proceedWithSettlement, false);
    assert.ok(result2.violations.some(v => v.code === 'ATTESTATION_REPLAYED'));
  });

  it('does not update state on rejection', async () => {
    // Send a bad payment (expired)
    const request = await buildPaymentRequest();
    const futureNow = now + 200000;
    const result = verifyX402Payment(request, facilitatorConfig, futureNow);
    assert.equal(result.decision, 'REJECT');

    // State should still be zero (no debit happened)
    const state = facilitatorConfig.getState('x402-test-mandate');
    assert.equal(state.spent, 0);
    assert.equal(state.orders, 0);
  });
});

describe('x402 adapter: payment request structure', () => {
  beforeEach(setup);

  it('creates a valid payment request', async () => {
    const mandateData = defaultMandateData();
    const signedMandate = await issueMandate({ mandate: mandateData, principalKeyPair: principalKp });
    const order = defaultOrder();
    const signedOrder = await signCart(order, merchantKp);
    const traceHash = hashCanonicalHex({ prompt: 'test' });
    const signedAttestation = await attestOrder({
      agentKeyPair: agentKp,
      agentId: 'x402-agent',
      modelVersion: 'test-v1',
      mandateHash: signedMandate.mandateHash,
      order,
      traceHash,
      timestamp: now,
    });

    const request = createX402PaymentRequest(signedMandate, signedOrder, signedAttestation);

    assert.equal(request.version, 'x402-mandate-v1');
    assert.ok(request.mandatePayload);
    assert.ok(request.mandatePayload.signedMandate);
    assert.ok(request.mandatePayload.signedOrder);
    assert.ok(request.mandatePayload.signedAttestation);
    assert.equal(request.mandatePayload.signedMandate.mandate.mandateId, 'x402-test-mandate');
  });
});
