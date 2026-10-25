/**
 * E2E: full mandate clearing flow.
 * 1. approve + buy → APPROVE
 * 2. replay → REJECT
 * 3. evil mode → REJECT
 * 4. budget exceeded → REJECT
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateEd25519KeyPair,
  attestOrder,
  hashCanonicalHex,
  type Order,
  type SignedMandate,
  type SignedOrder,
  type SignedAttestation,
} from 'agent-mandate-sdk';
import { app as approveApp, setPrincipalKey, encodeMandateRequest } from 'mandate-approve/src/server.js';
import { app as verifierApp } from 'mandate-verifier/src/server.js';
import { app as shopApp, setMerchantKey } from 'mandate-shop/src/server.js';

const principalKp = generateEd25519KeyPair();
const agentKp = generateEd25519KeyPair();
const merchantKp = generateEd25519KeyPair();

setPrincipalKey(principalKp);
setMerchantKey(merchantKp);

let approveServer: any, verifierServer: any, shopServer: any;
let approvePort: number, verifierPort: number, shopPort: number;
let signedMandate: SignedMandate;

// Store last successful verify payload for replay test
let lastPayload: { signedMandate: SignedMandate; signedOrder: SignedOrder; signedAttestation: SignedAttestation };

async function getMandate(): Promise<SignedMandate> {
  const req = {
    mandateId: `e2e-${Date.now()}`,
    agent: { id: 'e2e-agent', scheme: 'ed25519' as const, pubkey: agentKp.pubkey },
    constraints: { currency: 'USD', maxTotal: 5000, maxPerOrder: 3000, categories: ['api-credits'], merchants: ['north7.ai'] },
    validHours: 1,
  };
  const b64 = encodeMandateRequest(req);
  const res = await fetch(`http://127.0.0.1:${approvePort}/approve`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ req: b64 }),
  });
  return ((await res.json()) as any).signedMandate;
}

async function doBuy(mandate: SignedMandate, sku: string, qty: number, evil?: boolean) {
  const orderId = `ord-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const cartRes = await fetch(`http://127.0.0.1:${shopPort}/cart`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ orderId, items: [{ sku, qty }] }),
  });
  const { signedOrder } = (await cartRes.json()) as any;

  if (evil) signedOrder.merchant = 'evil-shop.darkweb.io';

  const plainOrder: Order = {
    orderId: signedOrder.orderId, merchant: signedOrder.merchant,
    currency: signedOrder.currency, items: signedOrder.items,
    total: signedOrder.total, createdAt: signedOrder.createdAt,
  };

  const traceHash = hashCanonicalHex({ input: `buy ${sku} x${qty}`, evil, ts: Date.now() });
  const signedAttestation = await attestOrder({
    agentKeyPair: agentKp, agentId: 'e2e-agent', modelVersion: 'e2e-v1',
    mandateHash: mandate.mandateHash, order: plainOrder,
    traceHash, timestamp: Math.floor(Date.now() / 1000),
  });

  const payload = { signedMandate: mandate, signedOrder, signedAttestation };
  lastPayload = payload;

  const verifyRes = await fetch(`http://127.0.0.1:${verifierPort}/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return { status: verifyRes.status, body: (await verifyRes.json()) as any };
}

describe('E2E: mandate clearing flow', () => {
  before(() => {
    approveServer = approveApp.listen(0);
    verifierServer = verifierApp.listen(0);
    shopServer = shopApp.listen(0);
    approvePort = (approveServer.address() as any).port;
    verifierPort = (verifierServer.address() as any).port;
    shopPort = (shopServer.address() as any).port;
  });

  after(() => { approveServer.close(); verifierServer.close(); shopServer.close(); });

  it('1. approve + buy → APPROVE', async () => {
    signedMandate = await getMandate();
    assert.ok(signedMandate.mandateHash);
    const r = await doBuy(signedMandate, 'credits-1000', 1);
    assert.equal(r.status, 200);
    assert.equal(r.body.decision, 'APPROVE');
    assert.equal(r.body.remainingBudget, 4000);
  });

  it('2. replay exact same request → REJECT', async () => {
    // Send the EXACT same payload again (same attestation hash)
    const res = await fetch(`http://127.0.0.1:${verifierPort}/verify`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(lastPayload),
    });
    assert.equal(res.status, 402);
    const body = (await res.json()) as any;
    assert.equal(body.decision, 'REJECT');
    assert.ok(body.violations.some((v: any) => v.code === 'ATTESTATION_REPLAYED'));
  });

  it('3. evil mode → REJECT', async () => {
    const r = await doBuy(signedMandate, 'credits-1000', 1, true);
    assert.equal(r.status, 402);
    assert.equal(r.body.decision, 'REJECT');
    assert.equal(r.body.liability, 'AGENT_PROVIDER');
  });

  it('4. buy until BUDGET_EXCEEDED', async () => {
    // Spent 1000. Buy 2000 more → 3000 total → OK
    const r1 = await doBuy(signedMandate, 'credits-1000', 2);
    assert.equal(r1.body.decision, 'APPROVE');
    // Now at 3000. Buy 3000 → 6000 > 5000 budget
    const r2 = await doBuy(signedMandate, 'credits-1000', 3);
    assert.equal(r2.status, 402);
    assert.ok(r2.body.violations.some((v: any) => v.code === 'BUDGET_EXCEEDED'));
  });
});
