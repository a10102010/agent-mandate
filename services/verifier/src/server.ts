/**
 * Mandate Clearing Verifier Service
 *
 * Wraps the pure verifyOrder in a stateful HTTP server.
 * POST /verify — direct verification endpoint
 * GET /verdicts/:id — retrieve a verdict
 * GET /agents/:pubkey/reputation — agent reputation
 */

import express from 'express';
import pg from 'pg';
import { verifyOrder, InMemoryNonceRegistry, type VerifierState } from 'agent-mandate-sdk';
import { PgStore } from './pg-store.js';
import { PreloadedNonceRegistry } from './pg-nonce.js';
import { mandateMiddleware } from './middleware.js';

const app = express();
app.use(express.json({ limit: '1mb' }));

// Database connection
const DATABASE_URL = process.env.DATABASE_URL ?? 'postgresql://mandate:mandate@localhost:5432/mandate';
const pool = new pg.Pool({ connectionString: DATABASE_URL });
const store = new PgStore(pool);

// In-memory fallback when no Postgres (for unit tests)
const inMemoryStates = new Map<string, VerifierState>();
const inMemoryNonce = new InMemoryNonceRegistry();

/**
 * POST /verify
 * Direct verification: body contains { signedMandate, signedOrder, signedAttestation }
 */
app.post('/verify', async (req, res) => {
  try {
    const { signedMandate, signedOrder, signedAttestation } = req.body;
    if (!signedMandate || !signedOrder || !signedAttestation) {
      return res.status(400).json({ error: 'Missing signedMandate, signedOrder, or signedAttestation' });
    }

    const mandateId = signedMandate.mandate.mandateId;
    const now = Math.floor(Date.now() / 1000);

    // Load state
    let state: VerifierState;
    let nonce: PreloadedNonceRegistry;

    try {
      state = await store.getState(mandateId);
      const hasNonce = await store.hasNonce(signedAttestation.attestationHash);
      nonce = new PreloadedNonceRegistry();
      if (hasNonce) nonce.load([signedAttestation.attestationHash]);
    } catch {
      // Postgres not available — use in-memory
      state = inMemoryStates.get(mandateId) ?? { spent: 0, orders: 0 };
      nonce = new PreloadedNonceRegistry();
      if (inMemoryNonce.has(signedAttestation.attestationHash)) {
        nonce.load([signedAttestation.attestationHash]);
      }
    }

    const result = verifyOrder({ signedMandate, order: signedOrder, signedAttestation, state, nonceRegistry: nonce, now });

    // Persist
    try {
      const verdictId = await store.recordVerdict(mandateId, signedOrder.total, result, signedAttestation.attestation.traceHash);
      res.status(result.decision === 'APPROVE' ? 200 : 402).json({ verdictId, ...result });
    } catch {
      // Fallback: in-memory tracking
      if (result.decision === 'APPROVE') {
        const cur = inMemoryStates.get(mandateId) ?? { spent: 0, orders: 0 };
        inMemoryStates.set(mandateId, { spent: cur.spent + signedOrder.total, orders: cur.orders + 1 });
        inMemoryNonce.add(result.attestationHash);
      }
      res.status(result.decision === 'APPROVE' ? 200 : 402).json(result);
    }
  } catch (err) {
    res.status(500).json({ error: 'Verification failed', detail: (err as Error).message });
  }
});

/** GET /verdicts/:id */
app.get('/verdicts/:id', async (req, res) => {
  try {
    const verdict = await store.getVerdict(Number(req.params.id));
    if (!verdict) return res.status(404).json({ error: 'Verdict not found' });
    res.json(verdict);
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

/** GET /agents/:pubkey/reputation */
app.get('/agents/:pubkey/reputation', async (req, res) => {
  try {
    const rep = await store.getReputation(req.params.pubkey);
    res.json({ agentPubkey: req.params.pubkey, ...rep, period: '30d' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

/** Health check */
app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'mandate-verifier' }));

/** Export middleware for other services to use */
export { mandateMiddleware, store };
export { app };

const PORT = parseInt(process.env.PORT ?? '3200');

if (process.argv[1]?.includes('server')) {
  app.listen(PORT, () => console.log(`[verifier] Mandate verifier on :${PORT}`));
}
