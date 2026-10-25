/**
 * Race condition tests — require a running Postgres.
 * Skip gracefully if DATABASE_URL is not reachable.
 *
 * Test 1: 20 parallel requests with same attestation → exactly 1 APPROVE.
 * Test 2: 10 parallel orders at 30% budget → max 3 APPROVE.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {
  generateEd25519KeyPair,
  issueMandate,
  signCart,
  attestOrder,
  hashCanonicalHex,
  type Order,
} from 'agent-mandate-sdk';
import { PgStore } from './pg-store.js';

const DATABASE_URL = process.env.DATABASE_URL ?? 'postgresql://mandate:mandate@localhost:5432/mandate';
let pool: pg.Pool;
let store: PgStore;
let pgAvailable = false;

const principalKp = generateEd25519KeyPair();
const agentKp = generateEd25519KeyPair();
const agent2Kp = generateEd25519KeyPair();
const merchantKp = generateEd25519KeyPair();
const now = Math.floor(Date.now() / 1000);

async function buildPayload(opts?: { mandateId?: string; maxTotal?: number; total?: number; agentKp?: typeof agentKp; agentId?: string }) {
  const akp = opts?.agentKp ?? agentKp;
  const signedMandate = await issueMandate({
    mandate: {
      mandateId: opts?.mandateId ?? `race-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      principal: { scheme: 'ed25519', pubkey: principalKp.pubkey },
      agent: { id: opts?.agentId ?? 'race-agent', scheme: 'ed25519', pubkey: akp.pubkey },
      constraints: { currency: 'USD', maxTotal: opts?.maxTotal ?? 10000, categories: ['api-credits'], merchants: ['north7.ai'] },
      validFrom: now - 60, validUntil: now + 86400,
      policy: { liabilityModel: 'mandate-scope-v1', disputeWindowSec: 604800 },
    },
    principalKeyPair: principalKp,
  });

  const total = opts?.total ?? 1000;
  const order: Order = {
    orderId: `ord-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    merchant: 'north7.ai', currency: 'USD',
    items: [{ sku: 'credits-1000', category: 'api-credits', unitPrice: total, qty: 1 }],
    total, createdAt: now,
  };

  const signedOrder = await signCart(order, merchantKp);
  const traceHash = hashCanonicalHex({ input: 'race test', ts: Date.now(), r: Math.random() });
  const signedAttestation = await attestOrder({
    agentKeyPair: akp, agentId: opts?.agentId ?? 'race-agent', modelVersion: 'test-v1',
    mandateHash: signedMandate.mandateHash, order, traceHash, timestamp: now,
  });

  return { signedMandate, signedOrder, signedAttestation };
}

describe('race: Postgres concurrency (skip if no DB)', () => {
  before(async () => {
    pool = new pg.Pool({ connectionString: DATABASE_URL, max: 25 });
    try {
      await pool.query('SELECT 1');
      pgAvailable = true;
      store = new PgStore(pool);
      // Reset tables
      await pool.query('DELETE FROM verdicts');
      await pool.query('DELETE FROM nonces');
      await pool.query('DELETE FROM ledger');
    } catch {
      console.log('[race] Postgres not available — skipping race tests');
    }
  });

  after(async () => {
    if (pool) await pool.end();
  });

  it('20 parallel replays → exactly 1 APPROVE', async (t) => {
    if (!pgAvailable) return t.skip('No Postgres');

    // Build ONE payload (same attestation for all 20 requests)
    const payload = await buildPayload();

    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        store.verifyAndRecord(
          payload.signedMandate, payload.signedOrder, payload.signedAttestation, now,
        ),
      ),
    );

    const approves = results.filter(r => r.result.decision === 'APPROVE');
    const rejects = results.filter(r => r.result.decision === 'REJECT');

    assert.equal(approves.length, 1, `Expected exactly 1 APPROVE, got ${approves.length}`);
    assert.equal(rejects.length, 19, `Expected 19 REJECTs, got ${rejects.length}`);

    // All rejects should be replay
    for (const r of rejects) {
      assert.ok(
        r.result.violations.some(v => v.code === 'ATTESTATION_REPLAYED'),
        'Rejected request should be ATTESTATION_REPLAYED',
      );
    }
  });

  it('10 parallel orders at 30% budget → max 3 APPROVE', async (t) => {
    if (!pgAvailable) return t.skip('No Postgres');

    const mandateId = `budget-race-${Date.now()}`;

    // Build 10 DIFFERENT orders (different attestations) but same mandate, each 30% of budget
    // Budget = 10000, each order = 3000 → max 3 can fit (9000 ≤ 10000)
    const payloads = await Promise.all(
      Array.from({ length: 10 }, () => buildPayload({ mandateId, maxTotal: 10000, total: 3000 })),
    );

    const results = await Promise.all(
      payloads.map(p =>
        store.verifyAndRecord(p.signedMandate, p.signedOrder, p.signedAttestation, now),
      ),
    );

    const approves = results.filter(r => r.result.decision === 'APPROVE');
    assert.ok(approves.length <= 3, `Expected ≤3 APPROVE, got ${approves.length}`);
    assert.ok(approves.length >= 1, `Expected ≥1 APPROVE, got ${approves.length}`);

    // Total spent should not exceed budget
    const totalSpent = approves.length * 3000;
    assert.ok(totalSpent <= 10000, `Total spent ${totalSpent} exceeds budget 10000`);
  });

  it('reputation: two agents, separate counts', async (t) => {
    if (!pgAvailable) return t.skip('No Postgres');

    // Clean slate
    await pool.query('DELETE FROM verdicts');
    await pool.query('DELETE FROM nonces');
    await pool.query('DELETE FROM ledger');

    // Agent 1: 2 approves
    for (let i = 0; i < 2; i++) {
      const p = await buildPayload({ agentKp: agentKp, agentId: 'agent-1' });
      await store.verifyAndRecord(p.signedMandate, p.signedOrder, p.signedAttestation, now);
    }

    // Agent 2: 1 approve + 1 reject (wrong merchant would need different setup, so just do 1)
    const p2 = await buildPayload({ agentKp: agent2Kp, agentId: 'agent-2' });
    await store.verifyAndRecord(p2.signedMandate, p2.signedOrder, p2.signedAttestation, now);

    const rep1 = await store.getReputation(agentKp.pubkey);
    const rep2 = await store.getReputation(agent2Kp.pubkey);

    assert.equal(rep1.approved, 2, `Agent 1 should have 2 approves, got ${rep1.approved}`);
    assert.equal(rep2.approved, 1, `Agent 2 should have 1 approve, got ${rep2.approved}`);
  });
});
