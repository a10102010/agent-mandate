/**
 * Express middleware for mandate verification.
 *
 * Reads X-Mandate and X-Attestation headers (base64 JSON),
 * calls verifyAndRecord (atomic: lock → verify → write),
 * REJECT → 402, APPROVE → next() with req.verdict.
 */

import type { Request, Response, NextFunction } from 'express';
import type { VerifyResult, SignedMandate, SignedOrder, SignedAttestation } from 'agent-mandate-sdk';
import type { PgStore } from './pg-store.js';

declare global {
  namespace Express {
    interface Request {
      verdict?: VerifyResult;
      mandateId?: string;
    }
  }
}

export function mandateMiddleware(store: PgStore) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const mandateHeader = req.headers['x-mandate'] as string | undefined;
    const attestationHeader = req.headers['x-attestation'] as string | undefined;

    if (!mandateHeader || !attestationHeader) {
      return res.status(402).json({
        error: 'Missing X-Mandate and/or X-Attestation headers',
        decision: 'REJECT',
        liability: 'NONE',
      });
    }

    let signedMandate: SignedMandate;
    let signedOrder: SignedOrder;
    let signedAttestation: SignedAttestation;

    try {
      const mandatePayload = JSON.parse(Buffer.from(mandateHeader, 'base64').toString());
      signedMandate = mandatePayload.signedMandate;
      signedOrder = mandatePayload.signedOrder;
      signedAttestation = JSON.parse(Buffer.from(attestationHeader, 'base64').toString());
    } catch {
      return res.status(400).json({ error: 'Malformed X-Mandate or X-Attestation header' });
    }

    const now = Math.floor(Date.now() / 1000);

    // Single atomic call: lock → verify → write
    const { verdictId, result } = await store.verifyAndRecord(
      signedMandate, signedOrder, signedAttestation, now,
    );

    if (result.decision === 'REJECT') {
      return res.status(402).json({ verdictId, ...result });
    }

    req.verdict = result;
    req.mandateId = signedMandate.mandate.mandateId;
    next();
  };
}
