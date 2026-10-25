/**
 * Express middleware for mandate verification.
 *
 * Reads X-Mandate and X-Attestation headers (base64 JSON),
 * calls verifyOrder, and either:
 * - REJECT: responds 402 with verdict in body
 * - APPROVE: calls next() with req.verdict attached
 *
 * verifyOrder is called as a pure function — all state is loaded
 * before the call and persisted after.
 */

import type { Request, Response, NextFunction } from 'express';
import {
  verifyOrder,
  type SignedMandate,
  type SignedOrder,
  type SignedAttestation,
  type VerifyResult,
} from 'agent-mandate-sdk';
import { PreloadedNonceRegistry } from './pg-nonce.js';
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

    const mandateId = signedMandate.mandate.mandateId;

    // Load state BEFORE calling pure verifyOrder
    const [state, hasNonce] = await Promise.all([
      store.getState(mandateId),
      store.hasNonce(signedAttestation.attestationHash),
    ]);

    // Build a sync NonceRegistry with pre-loaded data
    const nonceRegistry = new PreloadedNonceRegistry();
    if (hasNonce) nonceRegistry.load([signedAttestation.attestationHash]);

    const now = Math.floor(Date.now() / 1000);

    // Pure function call — no I/O inside
    const result = verifyOrder({
      signedMandate,
      order: signedOrder,
      signedAttestation,
      state,
      nonceRegistry,
      now,
    });

    // Persist AFTER the pure call
    const traceHash = signedAttestation.attestation.traceHash;
    const verdictId = await store.recordVerdict(mandateId, signedOrder.total, result, traceHash);

    if (result.decision === 'REJECT') {
      return res.status(402).json({
        verdictId,
        ...result,
      });
    }

    // APPROVE — attach to request and continue
    req.verdict = result;
    req.mandateId = mandateId;
    next();
  };
}
