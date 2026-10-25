/**
 * Postgres-backed NonceRegistry implementation.
 * Implements the NonceRegistry interface from the SDK.
 */

import type { Pool } from 'pg';
import type { NonceRegistry } from 'agent-mandate-sdk';

export class PgNonceRegistry implements NonceRegistry {
  constructor(private pool: Pool) {}

  has(hash: string): boolean {
    // Sync interface required by SDK — we use a pre-loaded cache.
    // In the verifier service, we call hasAsync before verifyOrder.
    throw new Error('Use hasAsync() in the verifier service layer');
  }

  add(hash: string): void {
    throw new Error('Use addAsync() in the verifier service layer');
  }

  async hasAsync(hash: string): Promise<boolean> {
    const res = await this.pool.query(
      'SELECT 1 FROM nonces WHERE attestation_hash = $1',
      [hash],
    );
    return res.rowCount! > 0;
  }

  async addAsync(hash: string, mandateId: string): Promise<void> {
    await this.pool.query(
      'INSERT INTO nonces (attestation_hash, mandate_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [hash, mandateId],
    );
  }
}

/**
 * Wrapper that pre-loads a set of hashes so the sync has()/add() work
 * within verifyOrder's synchronous execution.
 */
export class PreloadedNonceRegistry implements NonceRegistry {
  private seen = new Set<string>();
  private added: string[] = [];

  load(hashes: string[]): void {
    this.seen = new Set(hashes);
  }

  has(hash: string): boolean {
    return this.seen.has(hash);
  }

  add(hash: string): void {
    this.seen.add(hash);
    this.added.push(hash);
  }

  getAdded(): string[] {
    return this.added;
  }
}
