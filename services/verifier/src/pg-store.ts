import type { Pool, PoolClient } from 'pg';
import {
  verifyOrder,
  canonicalize,
  signEd25519,
  signatureToBase58,
  pubkeyFromBase58,
  verifyEd25519,
  signatureFromBase58,
  type SignedMandate,
  type SignedOrder,
  type SignedAttestation,
  type VerifyResult,
  type VerifierState,
} from 'agent-mandate-sdk';
import { PreloadedNonceRegistry } from './pg-nonce.js';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

export interface VerifyAndRecordResult {
  verdictId: number;
  result: VerifyResult;
  verdictSignature?: string;
  verifierPubkey?: string;
}

function loadVerifierKeyPair(): { secretKey: Uint8Array; pubkey: string } | null {
  const envKey = process.env.VERIFIER_SECRET_KEY;
  if (!envKey) return null;
  const secretKey = bs58.decode(envKey);
  const kp = nacl.sign.keyPair.fromSecretKey(secretKey);
  return { secretKey: kp.secretKey, pubkey: bs58.encode(kp.publicKey) };
}

function signVerdict(result: VerifyResult, ts: string, verifierKp: { secretKey: Uint8Array; pubkey: string }): string {
  const payload = canonicalize({
    attestationHash: result.attestationHash,
    decision: result.decision,
    liability: result.liability,
    mandateHash: result.mandateHash,
    orderHash: result.orderHash,
    remainingBudget: result.remainingBudget,
    ts,
    violations: result.violations,
  });
  const message = new TextEncoder().encode(payload);
  const sig = signEd25519(message, verifierKp.secretKey);
  return signatureToBase58(sig);
}

export class PgStore {
  pool: Pool;
  private verifierKp = loadVerifierKeyPair();

  constructor(pool: Pool) {
    this.pool = pool;
  }

  getVerifierPubkey(): string | null {
    return this.verifierKp?.pubkey ?? null;
  }

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
    const principalPubkey = signedMandate.mandate.principal.pubkey;

    const client: PoolClient = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        'INSERT INTO ledger (mandate_id, principal_pubkey) VALUES ($1, $2) ON CONFLICT (mandate_id) DO UPDATE SET principal_pubkey = COALESCE(ledger.principal_pubkey, $2)',
        [mandateId, principalPubkey],
      );
      const ledgerRes = await client.query('SELECT spent, orders, revoked_at FROM ledger WHERE mandate_id = $1 FOR UPDATE', [mandateId]);

      // Check revocation
      if (ledgerRes.rows[0].revoked_at) {
        const revokeResult: VerifyResult = {
          decision: 'REJECT', liability: 'AGENT_PROVIDER',
          violations: [{ code: 'MANDATE_REVOKED', detail: `Mandate revoked at ${ledgerRes.rows[0].revoked_at.toISOString()}` }],
          mandateHash: signedMandate.mandateHash, orderHash: '', attestationHash, remainingBudget: 0,
        };
        const ts = new Date().toISOString();
        const verdictSig = this.verifierKp ? signVerdict(revokeResult, ts, this.verifierKp) : null;
        const verdictRes = await client.query(
          `INSERT INTO verdicts (mandate_hash, order_hash, attestation_hash, trace_hash, decision, liability, violations, remaining_budget, agent_pubkey, verdict_signature, verifier_pubkey)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
          [signedMandate.mandateHash, '', attestationHash, traceHash, 'REJECT', 'AGENT_PROVIDER', JSON.stringify(revokeResult.violations), 0, agentPubkey, verdictSig, this.verifierKp?.pubkey ?? null],
        );
        await client.query('COMMIT');
        return { verdictId: verdictRes.rows[0].id, result: revokeResult, verdictSignature: verdictSig ?? undefined, verifierPubkey: this.verifierKp?.pubkey };
      }

      const state: VerifierState = { spent: Number(ledgerRes.rows[0].spent), orders: ledgerRes.rows[0].orders };
      const nonceRes = await client.query('SELECT 1 FROM nonces WHERE attestation_hash = $1', [attestationHash]);
      const nonceRegistry = new PreloadedNonceRegistry();
      if (nonceRes.rowCount! > 0) nonceRegistry.load([attestationHash]);

      const result = verifyOrder({ signedMandate, order: signedOrder, signedAttestation, state, nonceRegistry, now });

      const ts = new Date().toISOString();
      const verdictSig = this.verifierKp ? signVerdict(result, ts, this.verifierKp) : null;

      const verdictRes = await client.query(
        `INSERT INTO verdicts (mandate_hash, order_hash, attestation_hash, trace_hash, decision, liability, violations, remaining_budget, agent_pubkey, verdict_signature, verifier_pubkey)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
        [result.mandateHash, result.orderHash, attestationHash, traceHash, result.decision, result.liability, JSON.stringify(result.violations), result.remainingBudget, agentPubkey, verdictSig, this.verifierKp?.pubkey ?? null],
      );
      const verdictId = verdictRes.rows[0].id;

      if (result.decision === 'APPROVE') {
        await client.query('UPDATE ledger SET spent = spent + $2, orders = orders + 1 WHERE mandate_id = $1', [mandateId, signedOrder.total]);
        await client.query('INSERT INTO nonces (attestation_hash, mandate_id) VALUES ($1, $2)', [attestationHash, mandateId]);
      }

      await client.query('COMMIT');
      return { verdictId, result, verdictSignature: verdictSig ?? undefined, verifierPubkey: this.verifierKp?.pubkey };
    } catch (err) {
      await client.query('ROLLBACK');
      const pgErr = err as { code?: string; constraint?: string };
      if (pgErr.code === '23505' && pgErr.constraint === 'nonces_pkey') {
        const replayResult: VerifyResult = {
          decision: 'REJECT', liability: 'AGENT_PROVIDER',
          violations: [{ code: 'ATTESTATION_REPLAYED', detail: 'Concurrent replay detected by nonce constraint' }],
          mandateHash: signedMandate.mandateHash, orderHash: '', attestationHash, remainingBudget: 0,
        };
        const ts = new Date().toISOString();
        const verdictSig = this.verifierKp ? signVerdict(replayResult, ts, this.verifierKp) : null;
        const verdictRes = await this.pool.query(
          `INSERT INTO verdicts (mandate_hash, order_hash, attestation_hash, trace_hash, decision, liability, violations, remaining_budget, agent_pubkey, verdict_signature, verifier_pubkey)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
          [signedMandate.mandateHash, '', attestationHash, traceHash, 'REJECT', 'AGENT_PROVIDER', JSON.stringify(replayResult.violations), 0, agentPubkey, verdictSig, this.verifierKp?.pubkey ?? null],
        );
        return { verdictId: verdictRes.rows[0].id, result: replayResult, verdictSignature: verdictSig ?? undefined, verifierPubkey: this.verifierKp?.pubkey };
      }
      throw err;
    } finally {
      client.release();
    }
  }

  async revokeMandate(mandateId: string, principalPubkey: string, signature: string, mandateHash: string, ts: number): Promise<{ revoked: boolean; revokedAt: string }> {
    // Look up stored principal pubkey
    const ledgerRes = await this.pool.query('SELECT principal_pubkey, revoked_at FROM ledger WHERE mandate_id = $1', [mandateId]);
    if (ledgerRes.rowCount === 0) throw new Error('Mandate not found');
    if (ledgerRes.rows[0].revoked_at) throw new Error('Already revoked');

    const storedPubkey = ledgerRes.rows[0].principal_pubkey;
    if (storedPubkey && storedPubkey !== principalPubkey) {
      throw new Error('Principal pubkey mismatch');
    }

    // Verify Ed25519 signature over canonicalized revocation payload
    const message = new TextEncoder().encode(canonicalize({ action: 'revoke', mandateHash, mandateId, ts }));
    const sigBytes = signatureFromBase58(signature);
    const pubBytes = pubkeyFromBase58(principalPubkey);
    const valid = verifyEd25519(message, sigBytes, pubBytes);
    if (!valid) {
      throw new Error('Invalid signature');
    }

    const res = await this.pool.query(
      'UPDATE ledger SET revoked_at = now() WHERE mandate_id = $1 AND revoked_at IS NULL RETURNING revoked_at',
      [mandateId],
    );
    if (res.rowCount === 0) throw new Error('Already revoked');
    return { revoked: true, revokedAt: res.rows[0].revoked_at.toISOString() };
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
      `SELECT id, mandate_hash, order_hash, attestation_hash, agent_pubkey, decision, liability, violations, remaining_budget, verdict_signature, verifier_pubkey, created_at
       FROM verdicts ORDER BY id DESC LIMIT $1`, [limit]);
    return res.rows;
  }
}
