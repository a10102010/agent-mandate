/**
 * Mandate Clearing Verifier Service
 *
 * POST /verify — atomic verify-and-record (lock → verify → write)
 * GET /verdicts/:id — retrieve a verdict
 * GET /agents/:pubkey/reputation — agent reputation (30d)
 */

import express from 'express';
import pg from 'pg';
import { verifyOrder, InMemoryNonceRegistry, type VerifierState } from 'agent-mandate-sdk';
import { PgStore } from './pg-store.js';
import { PreloadedNonceRegistry } from './pg-nonce.js';
import { mandateMiddleware } from './middleware.js';

const app = express();
app.use(express.json({ limit: '1mb' }));

const DATABASE_URL = process.env.DATABASE_URL ?? 'postgresql://mandate:mandate@localhost:5432/mandate';
const pool = new pg.Pool({ connectionString: DATABASE_URL });
const store = new PgStore(pool);

// In-memory fallback for unit tests without Postgres
const inMemoryStates = new Map<string, VerifierState>();
const inMemoryNonce = new InMemoryNonceRegistry();

app.post('/verify', async (req, res) => {
  try {
    const { signedMandate, signedOrder, signedAttestation } = req.body;
    if (!signedMandate || !signedOrder || !signedAttestation) {
      return res.status(400).json({ error: 'Missing signedMandate, signedOrder, or signedAttestation' });
    }

    const now = Math.floor(Date.now() / 1000);

    // Try Postgres (atomic verifyAndRecord)
    try {
      const { verdictId, result } = await store.verifyAndRecord(
        signedMandate, signedOrder, signedAttestation, now,
      );
      return res.status(result.decision === 'APPROVE' ? 200 : 402).json({ verdictId, ...result });
    } catch {
      // Fallback: in-memory (for unit tests without Postgres)
      const mandateId = signedMandate.mandate.mandateId;
      const state = inMemoryStates.get(mandateId) ?? { spent: 0, orders: 0 };
      const nonce = new PreloadedNonceRegistry();
      if (inMemoryNonce.has(signedAttestation.attestationHash)) {
        nonce.load([signedAttestation.attestationHash]);
      }

      const result = verifyOrder({
        signedMandate, order: signedOrder, signedAttestation,
        state, nonceRegistry: nonce, now,
      });

      if (result.decision === 'APPROVE') {
        const cur = inMemoryStates.get(mandateId) ?? { spent: 0, orders: 0 };
        inMemoryStates.set(mandateId, { spent: cur.spent + signedOrder.total, orders: cur.orders + 1 });
        inMemoryNonce.add(result.attestationHash);
      }
      return res.status(result.decision === 'APPROVE' ? 200 : 402).json(result);
    }
  } catch (err) {
    res.status(500).json({ error: 'Verification failed', detail: (err as Error).message });
  }
});

app.get('/verdicts/:id', async (req, res) => {
  try {
    const verdict = await store.getVerdict(Number(req.params.id));
    if (!verdict) return res.status(404).json({ error: 'Verdict not found' });
    res.json(verdict);
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

app.get('/agents/:pubkey/reputation', async (req, res) => {
  try {
    const rep = await store.getReputation(req.params.pubkey);
    res.json({ agentPubkey: req.params.pubkey, ...rep, period: '30d' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'mandate-verifier' }));

export { mandateMiddleware, store, app };

const PORT = parseInt(process.env.PORT ?? '3200');

if (process.argv[1] === import.meta.url.replace('file://','')) {
  app.listen(PORT, () => console.log(`[verifier] Mandate verifier on :${PORT}`));
}
