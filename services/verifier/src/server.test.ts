import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateEd25519KeyPair,
  issueMandate,
  signCart,
  attestOrder,
  hashCanonicalHex,
  type Order,
  type Mandate,
} from 'agent-mandate-sdk';
import { app } from './server.js';

const principalKp = generateEd25519KeyPair();
const agentKp = generateEd25519KeyPair();
const merchantKp = generateEd25519KeyPair();
const now = Math.floor(Date.now() / 1000);

async function buildVerifyPayload(overrides?: { merchant?: string; total?: number; mandateId?: string; maxTotal?: number }) {
  const mandateData: Omit<Mandate, 'version' | 'nonce'> = {
    mandateId: overrides?.mandateId ?? `test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    principal: { scheme: 'ed25519', pubkey: principalKp.pubkey },
    agent: { id: 'test-agent', scheme: 'ed25519', pubkey: agentKp.pubkey },
    constraints: {
      currency: 'USD',
      maxTotal: overrides?.maxTotal ?? 10000,
      maxPerOrder: 5000,
      categories: ['api-credits'],
      merchants: ['north7.ai'],
    },
    validFrom: now - 60,
    validUntil: now + 86400,
    policy: { liabilityModel: 'mandate-scope-v1', disputeWindowSec: 604800 },
  };

  const signedMandate = await issueMandate({ mandate: mandateData, principalKeyPair: principalKp });

  const order: Order = {
    orderId: `ord-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    merchant: overrides?.merchant ?? 'north7.ai',
    currency: 'USD',
    items: [{ sku: 'credits-1000', category: 'api-credits', unitPrice: overrides?.total ?? 1000, qty: 1 }],
    total: overrides?.total ?? 1000,
    createdAt: now,
  };

  const signedOrder = await signCart(order, merchantKp);
  const traceHash = hashCanonicalHex({ input: 'buy credits', ts: Date.now(), r: Math.random() });
  const signedAttestation = await attestOrder({
    agentKeyPair: agentKp,
    agentId: 'test-agent',
    modelVersion: 'test-v1',
    mandateHash: signedMandate.mandateHash,
    order,
    traceHash,
    timestamp: now,
  });

  return { signedMandate, signedOrder, signedAttestation };
}

let server: ReturnType<typeof app.listen>;
let port: number;

describe('verifier: POST /verify (in-memory fallback)', () => {
  it('setup', () => {
    server = app.listen(0);
    port = (server.address() as any).port;
  });

  it('approves a valid order', async () => {
    const payload = await buildVerifyPayload();
    const res = await fetch(`http://127.0.0.1:${port}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json() as any;
    assert.equal(res.status, 200);
    assert.equal(data.decision, 'APPROVE');
    assert.equal(data.liability, 'PRINCIPAL');
    assert.equal(data.remainingBudget, 9000);
  });

  it('rejects wrong merchant (402)', async () => {
    const payload = await buildVerifyPayload({ merchant: 'evil-shop.com' });
    const res = await fetch(`http://127.0.0.1:${port}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json() as any;
    assert.equal(res.status, 402);
    assert.equal(data.decision, 'REJECT');
    assert.ok(data.violations.some((v: any) => v.code === 'MERCHANT_NOT_ALLOWED'));
  });

  it('rejects budget exceeded', async () => {
    const payload = await buildVerifyPayload({ total: 6000 });
    const res = await fetch(`http://127.0.0.1:${port}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json() as any;
    assert.equal(res.status, 402);
    assert.ok(data.violations.some((v: any) => v.code === 'ORDER_LIMIT_EXCEEDED'));
  });

  it('health check', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    const data = await res.json() as any;
    assert.equal(data.status, 'ok');
  });

  it('teardown', () => { server.close(); });
});
