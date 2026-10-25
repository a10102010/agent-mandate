/**
 * Postgres-backed verdict and ledger store.
 *
 * CRITICAL: verifyAndRecord runs the entire read→verify→write cycle
 * inside ONE transaction with FOR UPDATE row lock on the ledger.
 * This prevents race conditions on parallel orders for the same mandate.
 *
 * verifyOrder stays pure — it receives the locked state and returns a result.
 * All I/O happens outside the pure function.
 */

import type { Pool, PoolClient } from 'pg';
import {
  verifyOrder,
  type SignedMandate,
  type SignedOrder,
  type SignedAttestation,
  type VerifyResult,
  type VerifierState,
} from 'agent-mandate-sdk';
import { PreloadedNonceRegistry } from './pg-nonce.js';

export interface VerifyAndRecordResult {
  verdictId: number;
  result: VerifyResult;
}

export class PgStore {
  constructor(private pool: Pool) {}

  /**
   * Atomic verify-and-record: BEGIN → lock ledger → check nonce → verifyOrder → write → COMMIT.
   *
   * The ledger row is locked with FOR UPDATE so parallel requests for the same
   * mandate serialize. The nonce INSERT uses no ON CONFLICT — a duplicate is a
   * real error (concurrent replay) and triggers ROLLBACK → REJECT.
   */
  async verifyAndRecord(
    signedMandate: SignedMandate,
    signedOrder: SignedOrder,
    signedAttestation: SignedAttestation,
    now: number,
  ): Promise<VerifyAndRecordResult> {
    const mandateId = signedMandate.mandate.mandateId;
    const attestationHash = signedAttestation.attestationHash;
    const agentPubkey = signedAttestation.attestation.agentPubkey;
    const traceHash = signedAttestation.attestation.traceHash;

    const client: PoolClient = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // Ensure ledger row exists (idempotent)
      await client.query(
        'INSERT INTO ledger (mandate_id) VALUES ($1) ON CONFLICT DO NOTHING',
        [mandateId],
      );

      // Lock the ledger row — serializes parallel requests for this mandate
      const ledgerRes = await client.query(
        'SELECT spent, orders FROM ledger WHERE mandate_id = $1 FOR UPDATE',
        [mandateId],
      );
      const state: VerifierState = {
        spent: Number(ledgerRes.rows[0].spent),
        orders: ledgerRes.rows[0].orders,
      };

      // Check nonce (inside the transaction)
      const nonceRes = await client.query(
        'SELECT 1 FROM nonces WHERE attestation_hash = $1',
        [attestationHash],
      );

      // Build sync NonceRegistry with the locked data
      const nonceRegistry = new PreloadedNonceRegistry();
      if (nonceRes.rowCount! > 0) {
        nonceRegistry.load([attestationHash]);
      }

      // Pure function call — no I/O inside
      const result = verifyOrder({
        signedMandate,
        order: signedOrder,
        signedAttestation,
        state,
        nonceRegistry,
        now,
      });

      // Insert verdict
      const verdictRes = await client.query(
        `INSERT INTO verdicts
           (mandate_hash, order_hash, attestation_hash, trace_hash,
            decision, liability, violations, remaining_budget, agent_pubkey)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING id`,
        [
          result.mandateHash, result.orderHash, attestationHash, traceHash,
          result.decision, result.liability,
          JSON.stringify(result.violations), result.remainingBudget, agentPubkey,
        ],
      );
      const verdictId = verdictRes.rows[0].id;

      if (result.decision === 'APPROVE') {
        // Update ledger
        await client.query(
          'UPDATE ledger SET spent = spent + $2, orders = orders + 1 WHERE mandate_id = $1',
          [mandateId, signedOrder.total],
        );

        // Insert nonce — NO "ON CONFLICT DO NOTHING".
        // A conflict here means a concurrent replay slipped through;
        // the unique constraint catches it and the ROLLBACK makes this a REJECT.
        await client.query(
          'INSERT INTO nonces (attestation_hash, mandate_id) VALUES ($1, $2)',
          [attestationHash, mandateId],
        );
      }

      await client.query('COMMIT');
      return { verdictId, result };
    } catch (err) {
      await client.query('ROLLBACK');

      // Nonce uniqueness violation → replay
      const pgErr = err as { code?: string; constraint?: string };
      if (pgErr.code === '23505' && pgErr.constraint === 'nonces_pkey') {
        // Return a REJECT with ATTESTATION_REPLAYED
        const replayResult: VerifyResult = {
          decision: 'REJECT',
          liability: 'AGENT_PROVIDER',
          violations: [{ code: 'ATTESTATION_REPLAYED', detail: 'Concurrent replay detected by nonce constraint' }],
          mandateHash: signedMandate.mandateHash,
          orderHash: '',
          attestationHash,
          remainingBudget: 0,
        };

        // Record the rejection outside the failed transaction
        const verdictRes = await this.pool.query(
          `INSERT INTO verdicts
             (mandate_hash, order_hash, attestation_hash, trace_hash,
              decision, liability, violations, remaining_budget, agent_pubkey)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           RETURNING id`,
          [
            signedMandate.mandateHash, '', attestationHash, traceHash,
            'REJECT', 'AGENT_PROVIDER',
            JSON.stringify(replayResult.violations), 0, agentPubkey,
          ],
        );

        return { verdictId: verdictRes.rows[0].id, result: replayResult };
      }

      throw err;
    } finally {
      client.release();
    }
  }

  /** Get a verdict by ID. */
  async getVerdict(id: number): Promise<Record<string, unknown> | null> {
    const res = await this.pool.query('SELECT * FROM verdicts WHERE id = $1', [id]);
    return res.rowCount ? res.rows[0] : null;
  }

  /** Get agent reputation: approved + rejected counts over last 30 days. */
  async getReputation(agentPubkey: string): Promise<{ approved: number; rejected: number }> {
    const res = await this.pool.query(
      `SELECT
        COUNT(*) FILTER (WHERE decision = 'APPROVE') AS approved,
        COUNT(*) FILTER (WHERE decision = 'REJECT') AS rejected
       FROM verdicts
       WHERE agent_pubkey = $1 AND created_at > now() - interval '30 days'`,
      [agentPubkey],
    );
    return {
      approved: Number(res.rows[0].approved),
      rejected: Number(res.rows[0].rejected),
    };
  }
}
