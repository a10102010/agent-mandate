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
      await client.query('INSERT INTO ledger (mandate_id) VALUES ($1) ON CONFLICT DO NOTHING', [mandateId]);
      const ledgerRes = await client.query('SELECT spent, orders FROM ledger WHERE mandate_id = $1 FOR UPDATE', [mandateId]);
      const state: VerifierState = { spent: Number(ledgerRes.rows[0].spent), orders: ledgerRes.rows[0].orders };
      const nonceRes = await client.query('SELECT 1 FROM nonces WHERE attestation_hash = $1', [attestationHash]);
      const nonceRegistry = new PreloadedNonceRegistry();
      if (nonceRes.rowCount! > 0) nonceRegistry.load([attestationHash]);

      const result = verifyOrder({ signedMandate, order: signedOrder, signedAttestation, state, nonceRegistry, now });

      const verdictRes = await client.query(
        `INSERT INTO verdicts (mandate_hash, order_hash, attestation_hash, trace_hash, decision, liability, violations, remaining_budget, agent_pubkey)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
        [result.mandateHash, result.orderHash, attestationHash, traceHash, result.decision, result.liability, JSON.stringify(result.violations), result.remainingBudget, agentPubkey],
      );
      const verdictId = verdictRes.rows[0].id;

      if (result.decision === 'APPROVE') {
        await client.query('UPDATE ledger SET spent = spent + $2, orders = orders + 1 WHERE mandate_id = $1', [mandateId, signedOrder.total]);
        await client.query('INSERT INTO nonces (attestation_hash, mandate_id) VALUES ($1, $2)', [attestationHash, mandateId]);
      }

      await client.query('COMMIT');
      return { verdictId, result };
    } catch (err) {
      await client.query('ROLLBACK');
      const pgErr = err as { code?: string; constraint?: string };
      if (pgErr.code === '23505' && pgErr.constraint === 'nonces_pkey') {
        const replayResult: VerifyResult = {
          decision: 'REJECT', liability: 'AGENT_PROVIDER',
          violations: [{ code: 'ATTESTATION_REPLAYED', detail: 'Concurrent replay detected by nonce constraint' }],
          mandateHash: signedMandate.mandateHash, orderHash: '', attestationHash, remainingBudget: 0,
        };
        const verdictRes = await this.pool.query(
          `INSERT INTO verdicts (mandate_hash, order_hash, attestation_hash, trace_hash, decision, liability, violations, remaining_budget, agent_pubkey)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
          [signedMandate.mandateHash, '', attestationHash, traceHash, 'REJECT', 'AGENT_PROVIDER', JSON.stringify(replayResult.violations), 0, agentPubkey],
        );
        return { verdictId: verdictRes.rows[0].id, result: replayResult };
      }
      throw err;
    } finally {
      client.release();
    }
  }

  async getVerdict(id: number): Promise<Record<string, unknown> | null> {
    const res = await this.pool.query('SELECT * FROM verdicts WHERE id = $1', [id]);
    return res.rowCount ? res.rows[0] : null;
  }

  async getReputation(agentPubkey: string): Promise<{ approved: number; rejected: number }> {
    const res = await this.pool.query(
      `SELECT COUNT(*) FILTER (WHERE decision = 'APPROVE') AS approved, COUNT(*) FILTER (WHERE decision = 'REJECT') AS rejected
       FROM verdicts WHERE agent_pubkey = $1 AND created_at > now() - interval '30 days'`,
      [agentPubkey],
    );
    return { approved: Number(res.rows[0].approved), rejected: Number(res.rows[0].rejected) };
  }

  async getState(mandateId: string): Promise<VerifierState> {
    const res = await this.pool.query('SELECT spent, orders FROM ledger WHERE mandate_id = $1', [mandateId]);
    if (res.rowCount === 0) return { spent: 0, orders: 0 };
    return { spent: Number(res.rows[0].spent), orders: res.rows[0].orders };
  }

  async hasNonce(hash: string): Promise<boolean> {
    const res = await this.pool.query('SELECT 1 FROM nonces WHERE attestation_hash = $1', [hash]);
    return res.rowCount! > 0;
  }

  async getStats(): Promise<{ mandates: number; verdicts: number; approved: number; rejected: number }> {
    const [vRes, lRes] = await Promise.all([
      this.pool.query(`SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE decision = 'APPROVE') AS approved, COUNT(*) FILTER (WHERE decision = 'REJECT') AS rejected FROM verdicts`),
      this.pool.query('SELECT COUNT(*) AS total FROM ledger'),
    ]);
    return { mandates: Number(lRes.rows[0].total), verdicts: Number(vRes.rows[0].total), approved: Number(vRes.rows[0].approved), rejected: Number(vRes.rows[0].rejected) };
  }

  async listVerdicts(limit: number = 100): Promise<Array<Record<string, unknown>>> {
    const res = await this.pool.query(
      `SELECT id, mandate_hash, order_hash, attestation_hash, agent_pubkey, decision, liability, violations, remaining_budget, created_at
       FROM verdicts ORDER BY id DESC LIMIT $1`, [limit]);
    return res.rows;
  }
}
