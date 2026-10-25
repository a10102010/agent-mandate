import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  type Mandate,
  type Order,
} from 'agent-mandate-sdk';
import {
  fromVIRecord,
  fromVICart,
  toVI,
  parseVISdJwt,
  VITranslationError,
  type VIRecord,
  type VICart,
  type VIConstraint,
} from './vi-adapter.js';

// ── Helpers ──

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

function fakeAgentJwk(): { jwk: Record<string, string>; pubkeyRaw: Uint8Array } {
  const x = Buffer.alloc(32, 0xaa).toString('base64url');
  const y = Buffer.alloc(32, 0xbb).toString('base64url');
  const jwk = { kty: 'EC', crv: 'P-256', x, y, kid: 'agent-key-1' };
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(Buffer.alloc(32, 0xaa), 1);
  raw.set(Buffer.alloc(32, 0xbb), 33);
  return { jwk, pubkeyRaw: raw };
}

function fakeUserJwk(): Record<string, string> {
  const x = Buffer.alloc(32, 0xcc).toString('base64url');
  const y = Buffer.alloc(32, 0xdd).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x, y, kid: 'user-key-1' };
}

function buildVIRecord(opts?: {
  constraints?: VIConstraint[];
  immediateMode?: boolean;
}): VIRecord {
  const { jwk } = fakeAgentJwk();
  const userJwk = fakeUserJwk();

  const constraints = opts?.constraints ?? [
    { type: 'mandate.payment.budget', currency: 'EUR', max: 75000 },
    { type: 'mandate.payment.amount_range', currency: 'EUR', max: 15000 },
    { type: 'mandate.checkout.allowed_merchants', allowed: [{ id: 'shop-eu', name: 'Shop EU' }] },
  ];

  const vctCheckout = opts?.immediateMode ? 'mandate.checkout.1' : 'mandate.checkout.open.1';
  const vctPayment = opts?.immediateMode ? 'mandate.payment.1' : 'mandate.payment.open.1';

  // L1: issuer credential with user pubkey
  const l1SdJwt = fakeSdJwt({
    iss: 'https://www.mastercard.com',
    sub: 'user-001',
    iat: 1700000000,
    exp: 1731536000,
    vct: 'https://credentials.mastercard.com/card',
    cnf: { jwk: userJwk },
    pan_last_four: '1234',
    scheme: 'Mastercard',
  });

  // L2: user mandate with constraints
  const checkoutMandate = {
    vct: vctCheckout,
    cnf: { jwk: jwk },
    constraints: constraints.filter(c => c.type.includes('checkout')),
  };
  const paymentMandate = {
    vct: vctPayment,
    cnf: { jwk: jwk },
    constraints: constraints.filter(c => c.type.includes('payment')),
  };

  const checkoutDisc = fakeDisclosure('cs1', 'checkout_mandate', checkoutMandate);
  const paymentDisc = fakeDisclosure('ps1', 'payment_mandate', paymentMandate);

  const l2SdJwt = fakeSdJwt(
    {
      nonce: 'vi-nonce-1234567890ab',
      aud: 'https://agent.example.com',
      iat: 1700000000,
      exp: 1700086400,
      sd_hash: 'fake-l1-hash',
      _sd: ['hash1', 'hash2'],
    },
    [checkoutDisc, paymentDisc],
  );

  // L3: agent final values
  const l3PaymentSdJwt = fakeSdJwt({
    nonce: 'l3-nonce-abc',
    aud: 'https://payment.example.com',
    iat: 1700001000,
    exp: 1700004600,
    sd_hash: 'fake-l2-hash',
  });

  return {
    l1SdJwt,
    l2SdJwt,
    l3PaymentSdJwt,
    cart: {
      merchant_name: 'Shop EU',
      merchant_url: 'https://shop-eu.example',
      items: [
        { sku: 'ITEM-A', name: 'Widget A', quantity: 2, price: '49.99', currency: 'EUR' },
        { sku: 'ITEM-B', name: 'Gadget B', quantity: 1, price: '129.00', currency: 'EUR' },
      ],
      total: '228.98',
      currency: 'EUR',
    },
  };
}

// ── Tests ──

describe('VI adapter: SD-JWT parsing', () => {
  it('parses a VI SD-JWT', () => {
    const sdJwt = fakeSdJwt({ iss: 'https://mastercard.com', iat: 100 });
    const result = parseVISdJwt(sdJwt);
    assert.equal(result.header.alg, 'ES256');
    assert.equal(result.payload.iss, 'https://mastercard.com');
  });

  it('extracts disclosures', () => {
    const disc = fakeDisclosure('salt', 'email', 'user@test.com');
    const sdJwt = fakeSdJwt({ iss: 'test' }, [disc]);
    const result = parseVISdJwt(sdJwt);
    assert.equal(result.disclosures.length, 1);
    assert.equal(result.disclosures[0].key, 'email');
    assert.equal(result.disclosures[0].value, 'user@test.com');
  });
});

describe('VI adapter: fromVIRecord', () => {
  it('translates VI autonomous record to our mandate', () => {
    const record = buildVIRecord();
    const result = fromVIRecord({
      record,
      agentId: 'vi-agent',
      disputeWindowSec: 604800,
    });

    assert.equal(result.mandate.version, '1');
    assert.equal(result.mandate.agent.id, 'vi-agent');
    assert.equal(result.mandate.agent.scheme, 'es256');
    assert.equal(result.mandate.constraints.currency, 'EUR');
    assert.equal(result.mandate.constraints.maxTotal, 75000);
    assert.equal(result.mandate.constraints.maxPerOrder, 15000);
    assert.deepEqual(result.mandate.constraints.merchants, ['shop-eu']);
    assert.equal(result.mandate.policy.liabilityModel, 'mandate-scope-v1');
    assert.equal(result.mandate.validFrom, 1700000000);
    assert.equal(result.mandate.validUntil, 1700086400);
    assert.ok(result.originalRecord);
  });

  it('translates cart to order', () => {
    const record = buildVIRecord();
    const result = fromVIRecord({
      record,
      agentId: 'vi-agent',
      disputeWindowSec: 0,
    });

    assert.ok(result.order);
    assert.equal(result.order!.merchant, 'Shop EU');
    assert.equal(result.order!.currency, 'EUR');
    assert.equal(result.order!.items.length, 2);
    assert.equal(result.order!.items[0].sku, 'ITEM-A');
    assert.equal(result.order!.items[0].unitPrice, 4999); // €49.99 → 4999 cents
    assert.equal(result.order!.items[0].qty, 2);
    assert.equal(result.order!.items[1].unitPrice, 12900);
    // Total: 4999*2 + 12900*1 = 22898
    assert.equal(result.order!.total, 22898);
  });

  it('extracts L3 attestation fields', () => {
    const record = buildVIRecord();
    const result = fromVIRecord({
      record,
      agentId: 'vi-agent',
      disputeWindowSec: 0,
    });

    assert.ok(result.attestationFields);
    assert.equal(result.attestationFields!.agentId, 'vi-agent');
    assert.equal(result.attestationFields!.timestamp, 1700001000);
  });

  it('rejects immediate mode (no agent delegation)', () => {
    const record = buildVIRecord({ immediateMode: true });

    assert.throws(
      () => fromVIRecord({ record, agentId: 'test', disputeWindowSec: 0 }),
      (err: Error) => err instanceof VITranslationError && err.code === 'WRONG_MODE',
    );
  });

  it('fails when no budget constraint exists', () => {
    const record = buildVIRecord({
      constraints: [
        // Amount range but no budget
        { type: 'mandate.payment.amount_range', currency: 'USD', max: 5000 },
      ],
    });

    assert.throws(
      () => fromVIRecord({ record, agentId: 'test', disputeWindowSec: 0 }),
      (err: Error) => err instanceof VITranslationError && err.code === 'MISSING_REQUIRED',
    );
  });
});

describe('VI adapter: fromVICart', () => {
  it('converts VI cart to our order', () => {
    const cart: VICart = {
      merchant_name: 'Test Shop',
      merchant_url: 'https://test.shop',
      items: [
        { sku: 'T-SHIRT', name: 'Plain T-Shirt', quantity: 3, price: '19.99', currency: 'USD' },
      ],
      total: '59.97',
      currency: 'USD',
    };

    const order = fromVICart(cart);
    assert.equal(order.merchant, 'Test Shop');
    assert.equal(order.items.length, 1);
    assert.equal(order.items[0].unitPrice, 1999);
    assert.equal(order.items[0].qty, 3);
    assert.equal(order.total, 5997);
  });
});

describe('VI adapter: toVI', () => {
  it('translates our mandate to VI constraints', () => {
    const mandate: Mandate = {
      version: '1',
      mandateId: 'to-vi-test',
      principal: { scheme: 'es256', pubkey: 'fakepubkey' },
      agent: { id: 'agent-vi', scheme: 'es256', pubkey: 'fakeagentkey' },
      constraints: {
        currency: 'GBP',
        maxTotal: 200000,
        maxPerOrder: 50000,
        maxOrders: 20,
        merchants: ['uk-shop'],
        categories: ['fashion'], // lost in translation
        maxPerItem: 10000, // lost in translation
      },
      validFrom: 1700000000,
      validUntil: 1700086400,
      nonce: 'nonce1234567890ab',
      policy: { liabilityModel: 'mandate-scope-v1', disputeWindowSec: 604800 },
    };

    const result = toVI({ mandate });

    // Budget
    const budget = result.paymentConstraints.find(c => c.type === 'mandate.payment.budget');
    assert.ok(budget);
    assert.equal((budget as Record<string, unknown>).max, 200000);
    assert.equal((budget as Record<string, unknown>).currency, 'GBP');

    // Amount range
    const range = result.paymentConstraints.find(c => c.type === 'mandate.payment.amount_range');
    assert.ok(range);
    assert.equal((range as Record<string, unknown>).max, 50000);

    // Merchants
    const merchants = result.checkoutConstraints.find(
      c => c.type === 'mandate.checkout.allowed_merchants',
    );
    assert.ok(merchants);

    // Lost fields
    assert.ok(result.warnings.some(w => w.includes('categories')));
    assert.ok(result.warnings.some(w => w.includes('maxPerItem')));
    assert.ok(result.warnings.some(w => w.includes('liabilityModel')));
  });

  it('translates order to VI cart', () => {
    const mandate: Mandate = {
      version: '1',
      mandateId: 'cart-test',
      principal: { scheme: 'es256', pubkey: 'pk' },
      agent: { id: 'a', scheme: 'es256', pubkey: 'ak' },
      constraints: { currency: 'USD', maxTotal: 10000 },
      validFrom: 0,
      validUntil: 0,
      nonce: 'nonce1234567890ab',
      policy: { liabilityModel: 'mandate-scope-v1', disputeWindowSec: 0 },
    };

    const order: Order = {
      orderId: 'ord-1',
      merchant: 'Test Merch',
      currency: 'USD',
      items: [{ sku: 'SKU-X', category: 'cat', unitPrice: 2500, qty: 2 }],
      total: 5000,
      createdAt: 1700000000,
    };

    const result = toVI({ mandate, order });
    assert.ok(result.cart);
    assert.equal(result.cart!.merchant_name, 'Test Merch');
    assert.equal(result.cart!.items[0].price, '25.00');
    assert.equal(result.cart!.items[0].quantity, 2);
    assert.equal(result.cart!.total, '50.00');
  });

  it('rejects ed25519 mandates', () => {
    const mandate: Mandate = {
      version: '1',
      mandateId: 'ed-test',
      principal: { scheme: 'ed25519', pubkey: 'pk' },
      agent: { id: 'a', scheme: 'ed25519', pubkey: 'ak' },
      constraints: { currency: 'USD', maxTotal: 1000 },
      validFrom: 0,
      validUntil: 0,
      nonce: 'nonce1234567890ab',
      policy: { liabilityModel: 'mandate-scope-v1', disputeWindowSec: 0 },
    };

    assert.throws(
      () => toVI({ mandate }),
      (err: Error) => err instanceof VITranslationError && err.code === 'UNSUPPORTED_SCHEME',
    );
  });
});

describe('VI adapter: round-trip', () => {
  it('mandate → VI → mandate preserves core constraints', () => {
    const original: Mandate = {
      version: '1',
      mandateId: 'vi-roundtrip',
      principal: { scheme: 'es256', pubkey: 'fakepubkey' },
      agent: { id: 'agent-rt', scheme: 'es256', pubkey: 'fakeagentkey' },
      constraints: {
        currency: 'EUR',
        maxTotal: 100000,
        maxPerOrder: 25000,
        maxOrders: 10,
        merchants: ['eu-shop-1', 'eu-shop-2'],
      },
      validFrom: 1700000000,
      validUntil: 1700086400,
      nonce: 'roundtripnonce1234',
      policy: { liabilityModel: 'mandate-scope-v1', disputeWindowSec: 604800 },
    };

    // Step 1: Our mandate → VI constraints
    const vi = toVI({ mandate: original });

    // Step 2: Build fake VI SD-JWTs from those constraints
    const allConstraints = [...vi.checkoutConstraints, ...vi.paymentConstraints];
    const record = buildVIRecord({ constraints: allConstraints });

    // Step 3: VI → our mandate
    const result = fromVIRecord({
      record,
      agentId: 'agent-rt',
      disputeWindowSec: 604800,
    });

    // Core fields preserved
    assert.equal(result.mandate.constraints.currency, original.constraints.currency);
    assert.equal(result.mandate.constraints.maxTotal, original.constraints.maxTotal);
    assert.equal(result.mandate.constraints.maxPerOrder, original.constraints.maxPerOrder);
    assert.equal(result.mandate.constraints.maxOrders, original.constraints.maxOrders);
    assert.deepEqual(result.mandate.constraints.merchants, original.constraints.merchants);
    assert.equal(result.mandate.policy.liabilityModel, 'mandate-scope-v1');
    assert.equal(result.mandate.agent.id, 'agent-rt');
  });
});
