/**
 * Mandate Approval Service
 *
 * Principal-facing page where users review and sign mandates.
 * GET /approve?req=<base64> shows mandate details for approval.
 * POST /approve signs the mandate and returns it to the agent.
 * GET /mandates lists active mandates with remaining budget.
 */

import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  issueMandate,
  generateEd25519KeyPair,
  pubkeyToBase58,
  type Mandate,
  type SignedMandate,
  type KeyPair,
} from 'agent-mandate-sdk';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// In-memory stores
const activeMandates = new Map<string, { signedMandate: SignedMandate; spent: number; orders: number }>();
let principalKeyPair: KeyPair | null = null;

function getPrincipalKey(): KeyPair {
  if (!principalKeyPair) {
    principalKeyPair = generateEd25519KeyPair();
    console.log(`[approve] Generated principal key: ${principalKeyPair.pubkey}`);
  }
  return principalKeyPair;
}

/** Set key externally (for testing or env-based injection) */
export function setPrincipalKey(kp: KeyPair): void {
  principalKeyPair = kp;
}

export interface MandateRequest {
  mandateId: string;
  agent: { id: string; scheme: 'ed25519' | 'es256'; pubkey: string };
  constraints: Mandate['constraints'];
  validHours: number;
  callbackUrl?: string;
}

export function decodeMandateRequest(b64: string): MandateRequest {
  const json = Buffer.from(b64, 'base64url').toString('utf-8');
  const req = JSON.parse(json) as MandateRequest;
  if (!req.mandateId || !req.agent?.id || !req.constraints?.currency || !req.constraints?.maxTotal) {
    throw new Error('Invalid mandate request: missing required fields');
  }
  return req;
}

export function encodeMandateRequest(req: MandateRequest): string {
  return Buffer.from(JSON.stringify(req)).toString('base64url');
}

app.get('/approve', (req, res) => {
  const reqParam = req.query.req as string;
  if (!reqParam) return res.status(400).json({ error: 'Missing ?req= parameter' });
  try {
    decodeMandateRequest(reqParam); // validate
    res.sendFile(path.join(__dirname, '../public/index.html'));
  } catch (err) {
    res.status(400).json({ error: 'Invalid mandate request', detail: (err as Error).message });
  }
});

app.post('/approve', async (req, res) => {
  try {
    const { req: reqB64 } = req.body;
    if (!reqB64) return res.status(400).json({ error: 'Missing req field' });

    const mandateReq = decodeMandateRequest(reqB64);
    const kp = getPrincipalKey();
    const now = Math.floor(Date.now() / 1000);

    const signedMandate = await issueMandate({
      mandate: {
        mandateId: mandateReq.mandateId,
        principal: { scheme: kp.scheme, pubkey: kp.pubkey },
        agent: mandateReq.agent,
        constraints: mandateReq.constraints,
        validFrom: now,
        validUntil: now + mandateReq.validHours * 3600,
        policy: { liabilityModel: 'mandate-scope-v1', disputeWindowSec: 604800 },
      },
      principalKeyPair: kp,
    });

    activeMandates.set(mandateReq.mandateId, { signedMandate, spent: 0, orders: 0 });
    console.log(`[approve] Mandate ${mandateReq.mandateId} approved`);
    res.json({ signedMandate });
  } catch (err) {
    res.status(500).json({ error: 'Failed to sign mandate', detail: (err as Error).message });
  }
});

app.post('/reject', (_req, res) => {
  res.json({ rejected: true });
});

app.get('/mandates', (_req, res) => {
  const list = Array.from(activeMandates.entries()).map(([id, e]) => ({
    mandateId: id,
    agent: e.signedMandate.mandate.agent.id,
    currency: e.signedMandate.mandate.constraints.currency,
    maxTotal: e.signedMandate.mandate.constraints.maxTotal,
    spent: e.spent,
    remaining: e.signedMandate.mandate.constraints.maxTotal - e.spent,
    orders: e.orders,
    validUntil: new Date(e.signedMandate.mandate.validUntil * 1000).toISOString(),
  }));
  res.json({ mandates: list });
});

app.delete('/mandates/:id', (req, res) => {
  if (activeMandates.delete(req.params.id)) {
    res.json({ revoked: true, mandateId: req.params.id });
  } else {
    res.status(404).json({ error: 'Mandate not found' });
  }
});

app.get('/principal/pubkey', (_req, res) => {
  const kp = getPrincipalKey();
  res.json({ scheme: kp.scheme, pubkey: kp.pubkey });
});

const PORT = parseInt(process.env.PORT ?? '3100');
export { app };

if (process.argv[1]?.includes('server')) {
  app.listen(PORT, () => {
    console.log(`[approve] Mandate approval service on :${PORT}`);
    console.log(`[approve] Principal pubkey: ${getPrincipalKey().pubkey}`);
  });
}
