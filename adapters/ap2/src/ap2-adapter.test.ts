import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateEs256KeyPair,
  issueMandate,
  signCart,
  attestOrder,
  hashCanonicalHex,
  type Mandate,
  type Order,
} from 'agent-mandate-sdk';
import {
  fromAP2IntentMandate,
  fromAP2CheckoutJwt,
  toAP2,
  parseAP2SdJwt,
  AP2TranslationError,
  type AP2Constraint,
} from './ap2-adapter.js';

// ── Helpers to build fake AP2 SD-JWTs ──

function base64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

function fakeJwt(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  return `${base64url(header)}.${base64url(payload)}.fakesig`;
}

function fakeDisclosure(salt: string, key: string, value: unknown): string {
  return Buffer.from(JSON.stringify([salt, key, value])).toString('base64url');
}

function fakeSdJwt(
  payload: Record<string, unknown>,
  disclosures: string[] = [],
): string {
  const header = { alg: 'ES256', typ: 'sd+jwt' };
  const jwt = fakeJwt(header, payload);
  return [jwt, ...disclosures, ''].join('~');
}

// Build a fake AP2 agent JWK (P-256)
function fakeAgentJwk(): { jwk: Record<string, string>; pubkeyRaw: Uint8Array } {
  // Deterministic test key (not real, just valid-looking JWK coords)
  const x = Buffer.alloc(32, 0xaa).toString('base64url');
  const y = Buffer.alloc(32, 0xbb).toString('base64url');
  const jwk = { kty: 'EC', crv: 'P-256', x, y };
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(Buffer.alloc(32, 0xaa), 1);
  raw.set(Buffer.alloc(32, 0xbb), 33);
  return { jwk, pubkeyRaw: raw };
}

function fakeAP2OpenCheckout(constraints: AP2Constraint[], agentJwk: Record<string, string>): string {
  const checkoutMandate = {
    vct: 'mandate.checkout.open.1',
    cnf: { jwk: agentJwk },
    constraints,
  };
  const disc = fakeDisclosure('salt1', 'checkout', checkoutMandate);
  return fakeSdJwt(
    { vct: 'mandate.checkout.open.1', iat: 1700000000, exp: 1700086400, _sd: ['hash1'] },
    [disc],
  );
}

function fakeAP2OpenPayment(
  constraints: AP2Constraint[],
  agentJwk: Record<string, string>,
): string {
  const paymentMandate = {
    vct: 'mandate.payment.open.1',
    cnf: { jwk: agentJwk },
    constraints,
  };
  const disc = fakeDisclosure('salt2', 'payment', paymentMandate);
  return fakeSdJwt(
    {
      vct: 'mandate.payment.open.1',
      iat: 1700000000,
      exp: 1700086400,
      cnf: { jwk: agentJwk },
      constraints,
    },
    [disc],
  );
}

function fakeCheckoutJwt(): string {
  const header = { alg: 'ES256', typ: 'JWT' };
  const payload = {
    order_id: 'ORDER-001',
    merchant: { id: 'demo-merchant', name: 'Demo Merchant', website: 'https://demo.example' },
    line_items: [
      {
        id: 'line_1',
        product: { id: 'SHOE-001', title: 'Gold Sneaker', price: 199.99, currency: 'USD' },
        quantity: 1,
      },
      {
        id: 'line_2',
        product: { id: 'SOCK-001', title: 'Best Socks', price: 12.50, currency: 'USD' },
        quantity: 2,
      },
    ],
    total_price: 224.99,
    currency: 'USD',
  };
  return fakeJwt(header, payload);
}

// ── Tests ──

describe('AP2 adapter: SD-JWT parsing', () => {
  it('parses a minimal SD-JWT', () => {
    const sdJwt = fakeSdJwt({ iss: 'test', iat: 123 });
    const result = parseAP2SdJwt(sdJwt);
    assert.equal(result.header.alg, 'ES256');
    assert.equal(result.payload.iss, 'test');
    assert.equal(result.payload.iat, 123);
  });

  it('extracts disclosures', () => {
    const disc = fakeDisclosure('salt', 'email', 'alice@example.com');
    const sdJwt = fakeSdJwt({ iss: 'test' }, [disc]);
    const result = parseAP2SdJwt(sdJwt);
    assert.equal(result.disclosures.length, 1);
    assert.equal(result.disclosures[0].key, 'email');
    assert.equal(result.disclosures[0].value, 'alice@example.com');
  });

  it('rejects invalid JWT', () => {
    assert.throws(
      () => parseAP2SdJwt('not-a-jwt'),
      (err: Error) => err instanceof AP2TranslationError && err.code === 'INVALID_SD_JWT',
    );
  });
});

describe('AP2 adapter: fromAP2IntentMandate', () => {
  it('translates AP2 open mandates to our mandate', () => {
    const { jwk, pubkeyRaw } = fakeAgentJwk();
    const principalPubkey = new Uint8Array(65);
    principalPubkey[0] = 0x04;
    principalPubkey.set(Buffer.alloc(32, 0xcc), 1);
    principalPubkey.set(Buffer.alloc(32, 0xdd), 33);

    const checkoutSdJwt = fakeAP2OpenCheckout(
      [{ type: 'checkout.allowed_merchants', allowed: [{ id: 'merch-1', name: 'Merch 1' }] }],
      jwk,
    );
    const paymentSdJwt = fakeAP2OpenPayment(
      [
        { type: 'payment.budget', currency: 'USD', max: 50000 },
        { type: 'payment.amount_range', currency: 'USD', max: 20000 },
      ],
      jwk,
    );

    const result = fromAP2IntentMandate({
      checkoutSdJwt,
      paymentSdJwt,
      agentId: 'test-agent',
      principalPubkey,
      disputeWindowSec: 604800,
    });

    assert.equal(result.mandate.version, '1');
    assert.equal(result.mandate.agent.id, 'test-agent');
    assert.equal(result.mandate.agent.scheme, 'es256');
    assert.equal(result.mandate.constraints.currency, 'USD');
    assert.equal(result.mandate.constraints.maxTotal, 50000);
    assert.equal(result.mandate.constraints.maxPerOrder, 20000);
    assert.equal(result.mandate.policy.liabilityModel, 'mandate-scope-v1');
    assert.equal(result.mandate.policy.disputeWindowSec, 604800);
    assert.ok(result.originalCheckoutSdJwt);
    assert.ok(result.originalPaymentSdJwt);
  });

  it('rejects closed mandates (wrong mode)', () => {
    const { jwk } = fakeAgentJwk();
    const closedSdJwt = fakeSdJwt({
      vct: 'mandate.checkout.1', // closed, not open
      iat: 1700000000,
      exp: 1700086400,
    });

    assert.throws(
      () =>
        fromAP2IntentMandate({
          checkoutSdJwt: closedSdJwt,
          paymentSdJwt: closedSdJwt,
          agentId: 'test',
          principalPubkey: new Uint8Array(65),
          disputeWindowSec: 0,
        }),
      (err: Error) => err instanceof AP2TranslationError && err.code === 'WRONG_MODE',
    );
  });

  it('fails when no budget constraint exists', () => {
    const { jwk } = fakeAgentJwk();
    const checkoutSdJwt = fakeAP2OpenCheckout([], jwk);
    const paymentSdJwt = fakeAP2OpenPayment([], jwk); // no budget!

    assert.throws(
      () =>
        fromAP2IntentMandate({
          checkoutSdJwt,
          paymentSdJwt,
          agentId: 'test',
          principalPubkey: new Uint8Array(65),
          disputeWindowSec: 0,
        }),
      (err: Error) => err instanceof AP2TranslationError && err.code === 'MISSING_REQUIRED',
    );
  });
});

describe('AP2 adapter: fromAP2CheckoutJwt', () => {
  it('translates checkout JWT to our order', () => {
    const jwt = fakeCheckoutJwt();
    const { order, warnings } = fromAP2CheckoutJwt(jwt);

    assert.equal(order.orderId, 'ORDER-001');
    assert.equal(order.merchant, 'demo-merchant');
    assert.equal(order.currency, 'USD');
    assert.equal(order.items.length, 2);
    assert.equal(order.items[0].sku, 'SHOE-001');
    assert.equal(order.items[0].unitPrice, 19999); // $199.99 → 19999 cents
    assert.equal(order.items[0].qty, 1);
    assert.equal(order.items[1].sku, 'SOCK-001');
    assert.equal(order.items[1].unitPrice, 1250); // $12.50 → 1250 cents
    assert.equal(order.items[1].qty, 2);
    // Total: 19999 + 1250*2 = 22499
    assert.equal(order.total, 22499);
    assert.ok(warnings.some(w => w.includes('category')));
  });
});

describe('AP2 adapter: toAP2', () => {
  it('translates our mandate to AP2 constraints', () => {
    const mandate: Mandate = {
      version: '1',
      mandateId: 'test-mandate',
      principal: { scheme: 'es256', pubkey: 'fakepubkey' },
      agent: { id: 'agent-1', scheme: 'es256', pubkey: 'fakeagentkey' },
      constraints: {
        currency: 'EUR',
        maxTotal: 100000,
        maxPerOrder: 25000,
        maxOrders: 10,
        merchants: ['shop-a', 'shop-b'],
        skus: ['SKU-1', 'SKU-2'],
        categories: ['electronics'], // not expressible in AP2
        maxPerItem: 5000, // not expressible in AP2
      },
      validFrom: 1700000000,
      validUntil: 1700086400,
      nonce: 'abcdef1234567890',
      policy: { liabilityModel: 'mandate-scope-v1', disputeWindowSec: 604800 },
    };

    const result = toAP2(mandate);

    // Budget
    const budget = result.paymentConstraints.find(c => c.type === 'payment.budget');
    assert.ok(budget);
    assert.equal((budget as Record<string, unknown>).max, 100000);
    assert.equal((budget as Record<string, unknown>).currency, 'EUR');

    // Amount range
    const range = result.paymentConstraints.find(c => c.type === 'payment.amount_range');
    assert.ok(range);
    assert.equal((range as Record<string, unknown>).max, 25000);

    // Merchants
    const merchants = result.checkoutConstraints.find(c => c.type === 'checkout.allowed_merchants');
    assert.ok(merchants);
    const allowed = (merchants as Record<string, unknown>).allowed as Array<{ id: string }>;
    assert.equal(allowed.length, 2);
    assert.equal(allowed[0].id, 'shop-a');

    // Recurrence
    const recurrence = result.paymentConstraints.find(c => c.type === 'payment.agent_recurrence');
    assert.ok(recurrence);
    assert.equal((recurrence as Record<string, unknown>).max_occurrences, 10);

    // Warnings about lost fields
    assert.ok(result.warnings.some(w => w.includes('categories')));
    assert.ok(result.warnings.some(w => w.includes('maxPerItem')));
    assert.ok(result.warnings.some(w => w.includes('liabilityModel')));
  });

  it('rejects ed25519 mandates', () => {
    const mandate: Mandate = {
      version: '1',
      mandateId: 'test',
      principal: { scheme: 'ed25519', pubkey: 'fakepubkey' },
      agent: { id: 'a', scheme: 'ed25519', pubkey: 'fakeagentkey' },
      constraints: { currency: 'USD', maxTotal: 1000 },
      validFrom: 0,
      validUntil: 0,
      nonce: 'abcdef1234567890',
      policy: { liabilityModel: 'mandate-scope-v1', disputeWindowSec: 0 },
    };

    assert.throws(
      () => toAP2(mandate),
      (err: Error) => err instanceof AP2TranslationError && err.code === 'UNSUPPORTED_SCHEME',
    );
  });
});

describe('AP2 adapter: round-trip', () => {
  it('mandate → AP2 → mandate preserves core constraints', () => {
    const original: Mandate = {
      version: '1',
      mandateId: 'roundtrip-test',
      principal: { scheme: 'es256', pubkey: 'fakepubkey' },
      agent: { id: 'agent-rt', scheme: 'es256', pubkey: 'fakeagentkey' },
      constraints: {
        currency: 'USD',
        maxTotal: 50000,
        maxPerOrder: 10000,
        maxOrders: 5,
        merchants: ['merch-a'],
      },
      validFrom: 1700000000,
      validUntil: 1700086400,
      nonce: 'roundtripnonce1234',
      policy: { liabilityModel: 'mandate-scope-v1', disputeWindowSec: 604800 },
    };

    // Step 1: Our mandate → AP2 constraints
    const ap2 = toAP2(original);

    // Step 2: Build fake AP2 SD-JWTs from those constraints
    const { jwk, pubkeyRaw } = fakeAgentJwk();
    const checkoutSdJwt = fakeAP2OpenCheckout(ap2.checkoutConstraints, jwk);
    const paymentSdJwt = fakeAP2OpenPayment(ap2.paymentConstraints, jwk);

    // Step 3: AP2 → our mandate
    const principalPubkey = new Uint8Array(65);
    principalPubkey[0] = 0x04;
    principalPubkey.set(Buffer.alloc(32, 0xcc), 1);
    principalPubkey.set(Buffer.alloc(32, 0xdd), 33);

    const result = fromAP2IntentMandate({
      checkoutSdJwt,
      paymentSdJwt,
      agentId: 'agent-rt',
      principalPubkey,
      disputeWindowSec: 604800,
    });

    // Core constraints preserved
    assert.equal(result.mandate.constraints.currency, original.constraints.currency);
    assert.equal(result.mandate.constraints.maxTotal, original.constraints.maxTotal);
    assert.equal(result.mandate.constraints.maxPerOrder, original.constraints.maxPerOrder);
    assert.equal(result.mandate.constraints.maxOrders, original.constraints.maxOrders);
    assert.deepEqual(result.mandate.constraints.merchants, original.constraints.merchants);
    assert.equal(result.mandate.policy.liabilityModel, 'mandate-scope-v1');
    assert.equal(result.mandate.policy.disputeWindowSec, 604800);
    assert.equal(result.mandate.agent.id, 'agent-rt');
  });
});
