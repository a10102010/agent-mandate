/**
 * Postgres-backed verdict and ledger store.
 * Atomic: ledger update + verdict insert in one transaction.
 */

import type { Pool, PoolClient } from 'pg';
import type { VerifyResult, VerifierState } from 'agent-mandate-sdk';

export class PgStore {
  constructor(private pool: Pool) {}

  /** Get current state for a mandate (spent + orders). */
  async getState(mandateId: string): Promise<VerifierState> {
    const res = await this.pool.query(
      'SELECT spent, orders FROM ledger WHERE mandate_id = $1',
      [mandateId],
    );
    if (res.rowCount === 0) return { spent: 0, orders: 0 };
    return { spent: Number(res.rows[0].spent), orders: res.rows[0].orders };
  }

  /** Check if an attestation hash has been seen. */
  async hasNonce(hash: string): Promise<boolean> {
    const res = await this.pool.query(
      'SELECT 1 FROM nonces WHERE attestation_hash = $1',
      [hash],
    );
    return res.rowCount! > 0;
  }

  /**
   * Atomically: insert verdict + update ledger + register nonce.
   * This prevents race conditions on parallel orders for the same mandate.
   */
  async recordVerdict(
    mandateId: string,
    orderTotal: number,
    result: VerifyResult,
    traceHash: string,
  ): Promise<number> {
    const client: PoolClient = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // Insert verdict
      const verdictRes = await client.query(
        `INSERT INTO verdicts (mandate_hash, order_hash, attestation_hash, trace_hash, decision, liability, violations, remaining_budget)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
        [
          result.mandateHash,
          result.orderHash,
          result.attestationHash,
          traceHash,
          result.decision,
          result.liability,
          JSON.stringify(result.violations),
          result.remainingBudget,
        ],
      );
      const verdictId = verdictRes.rows[0].id;

      if (result.decision === 'APPROVE') {
        // Update ledger atomically
        await client.query(
          `INSERT INTO ledger (mandate_id, spent, orders) VALUES ($1, $2, 1)
           ON CONFLICT (mandate_id) DO UPDATE SET spent = ledger.spent + $2, orders = ledger.orders + 1`,
          [mandateId, orderTotal],
        );

        // Register nonce
        await client.query(
          'INSERT INTO nonces (attestation_hash, mandate_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [result.attestationHash, mandateId],
        );
      }

      await client.query('COMMIT');
      return verdictId;
    } catch (err) {
      await client.query('ROLLBACK');
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
    // Agent pubkey is in the mandate, which is in the attestation.
    // We count verdicts where the mandate's agent matches.
    // For now, we count all verdicts (simplified — production would join on mandate data).
    const res = await this.pool.query(
      `SELECT
        COUNT(*) FILTER (WHERE decision = 'APPROVE') AS approved,
        COUNT(*) FILTER (WHERE decision = 'REJECT') AS rejected
       FROM verdicts
       WHERE created_at > now() - interval '30 days'`,
    );
    return {
      approved: Number(res.rows[0].approved),
      rejected: Number(res.rows[0].rejected),
    };
  }
}
