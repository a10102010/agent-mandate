/**
 * MandateAgent — handles keys, mandates, orders, and attestations.
 *
 * Agent key is generated once and persisted to ~/.mandate-clearing/.
 * Mandates are stored locally. Trace is the hash of all tool calls in the session.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  generateEd25519KeyPair,
  attestOrder,
  hashCanonicalHex,
  type KeyPair,
  type SignedMandate,
  type Order,
} from 'agent-mandate-sdk';

const STATE_DIR = path.join(os.homedir(), '.mandate-clearing');

export class MandateAgent {
  private baseUrl: string;
  private keyPair: KeyPair | null = null;
  private mandates = new Map<string, SignedMandate>();
  private latestMandateId: string | null = null;
  private toolCalls: Array<{ tool: string; args: unknown; ts: number }> = [];

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.ensureStateDir();
    this.loadState();
  }

  private ensureStateDir(): void {
    if (!fs.existsSync(STATE_DIR)) {
      fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
    }
  }

  private getKeyPair(): KeyPair {
    if (this.keyPair) return this.keyPair;

    const keyFile = path.join(STATE_DIR, 'agent-key.json');
    if (fs.existsSync(keyFile)) {
      const data = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
      this.keyPair = {
        scheme: data.scheme,
        publicKey: Buffer.from(data.publicKey, 'hex'),
        secretKey: Buffer.from(data.secretKey, 'hex'),
        pubkey: data.pubkey,
      };
    } else {
      this.keyPair = generateEd25519KeyPair();
      fs.writeFileSync(keyFile, JSON.stringify({
        scheme: this.keyPair.scheme,
        publicKey: Buffer.from(this.keyPair.publicKey).toString('hex'),
        secretKey: Buffer.from(this.keyPair.secretKey).toString('hex'),
        pubkey: this.keyPair.pubkey,
      }), { mode: 0o600 });
    }

    return this.keyPair;
  }

  private loadState(): void {
    const mandateFile = path.join(STATE_DIR, 'mandates.json');
    if (fs.existsSync(mandateFile)) {
      try {
        const data = JSON.parse(fs.readFileSync(mandateFile, 'utf-8'));
        for (const [id, m] of Object.entries(data)) {
          this.mandates.set(id, m as SignedMandate);
        }
        // Find most recent valid mandate
        const now = Math.floor(Date.now() / 1000);
        for (const [id, m] of this.mandates) {
          if (m.mandate.validUntil > now) {
            this.latestMandateId = id;
          }
        }
      } catch { /* ignore corrupt state */ }
    }
  }

  private saveState(): void {
    const mandateFile = path.join(STATE_DIR, 'mandates.json');
    const obj: Record<string, SignedMandate> = {};
    for (const [id, m] of this.mandates) obj[id] = m;
    fs.writeFileSync(mandateFile, JSON.stringify(obj, null, 2), { mode: 0o600 });
  }

  private recordToolCall(tool: string, args: unknown): void {
    this.toolCalls.push({ tool, args, ts: Date.now() });
  }

  private getTraceHash(): string {
    return hashCanonicalHex({ toolCalls: this.toolCalls });
  }

  async requestMandate(opts: {
    categories: string[];
    merchants: string[];
    maxPerOrder?: number;
    maxTotal: number;
    hours: number;
  }): Promise<Record<string, unknown>> {
    this.recordToolCall('request_mandate', opts);
    const kp = this.getKeyPair();

    const mandateReq = {
      mandateId: `mcp-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      agent: { id: 'mcp-agent', scheme: 'ed25519' as const, pubkey: kp.pubkey },
      constraints: {
        currency: 'USD',
        maxTotal: opts.maxTotal,
        maxPerOrder: opts.maxPerOrder,
        categories: opts.categories,
        merchants: opts.merchants,
      },
      validHours: opts.hours,
    };

    const b64 = Buffer.from(JSON.stringify(mandateReq)).toString('base64url');
    const approveUrl = `${this.baseUrl}/approve?req=${b64}`;

    // POST to approve endpoint (auto-approve for server flow)
    const res = await fetch(`${this.baseUrl}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ req: b64 }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      return {
        status: 'PENDING',
        approveUrl,
        message: `Open this URL to approve the mandate: ${approveUrl}`,
        error: (err as any).error,
      };
    }

    const data = await res.json() as any;
    const signedMandate: SignedMandate = data.signedMandate;

    this.mandates.set(signedMandate.mandate.mandateId, signedMandate);
    this.latestMandateId = signedMandate.mandate.mandateId;
    this.saveState();

    return {
      status: 'APPROVED',
      mandateId: signedMandate.mandate.mandateId,
      budget: `${(signedMandate.mandate.constraints.maxTotal / 100).toFixed(2)} ${signedMandate.mandate.constraints.currency}`,
      validUntil: new Date(signedMandate.mandate.validUntil * 1000).toISOString(),
      merchants: signedMandate.mandate.constraints.merchants,
      categories: signedMandate.mandate.constraints.categories,
      agentPubkey: kp.pubkey,
    };
  }

  async listMandates(): Promise<Record<string, unknown>> {
    this.recordToolCall('list_mandates', {});
    const now = Math.floor(Date.now() / 1000);
    const list = [];

    for (const [id, m] of this.mandates) {
      const expired = m.mandate.validUntil < now;
      list.push({
        mandateId: id,
        currency: m.mandate.constraints.currency,
        maxTotal: m.mandate.constraints.maxTotal,
        merchants: m.mandate.constraints.merchants,
        validUntil: new Date(m.mandate.validUntil * 1000).toISOString(),
        expired,
      });
    }

    return { mandates: list, active: list.filter(m => !m.expired).length };
  }

  async buyCredits(opts: {
    sku: string;
    qty: number;
    mandateId?: string;
  }): Promise<Record<string, unknown>> {
    this.recordToolCall('buy_credits', opts);
    const kp = this.getKeyPair();

    const mandateId = opts.mandateId ?? this.latestMandateId;
    if (!mandateId) return { error: 'No mandate available. Use request_mandate first.' };

    const signedMandate = this.mandates.get(mandateId);
    if (!signedMandate) return { error: `Mandate ${mandateId} not found locally.` };

    // Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (signedMandate.mandate.validUntil < now) {
      return { error: `Mandate ${mandateId} expired at ${new Date(signedMandate.mandate.validUntil * 1000).toISOString()}` };
    }

    // Get signed cart from shop
    const orderId = `mcp-ord-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const cartRes = await fetch(`${this.baseUrl}/shop/cart`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ orderId, items: [{ sku: opts.sku, qty: opts.qty }] }),
    });

    if (!cartRes.ok) {
      const err = await cartRes.json().catch(() => ({ error: cartRes.statusText }));
      return { error: `Cart failed: ${(err as any).error ?? cartRes.statusText}` };
    }

    const { signedOrder } = await cartRes.json() as any;

    // Build plain order for attestation
    const plainOrder: Order = {
      orderId: signedOrder.orderId,
      merchant: signedOrder.merchant,
      currency: signedOrder.currency,
      items: signedOrder.items,
      total: signedOrder.total,
      createdAt: signedOrder.createdAt,
    };

    // Attest with trace hash
    const traceHash = this.getTraceHash();
    const signedAttestation = await attestOrder({
      agentKeyPair: kp,
      agentId: 'mcp-agent',
      modelVersion: 'mcp-v0.1',
      mandateHash: signedMandate.mandateHash,
      order: plainOrder,
      traceHash,
      timestamp: now,
    });

    // Send to verifier
    const verifyRes = await fetch(`${this.baseUrl}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ signedMandate, signedOrder, signedAttestation }),
    });

    const verdict = await verifyRes.json() as any;

    if (verdict.decision === 'APPROVE') {
      return {
        decision: 'APPROVE',
        verdictId: verdict.verdictId,
        sku: opts.sku,
        qty: opts.qty,
        totalPaid: `${(signedOrder.total / 100).toFixed(2)} USD`,
        remainingBudget: `${(verdict.remainingBudget / 100).toFixed(2)} USD`,
        mandateId,
      };
    }

    // REJECT — return violations in readable form, not as error
    const violations = (verdict.violations ?? []).map((v: any) =>
      `${v.code}: ${v.detail}`
    );

    return {
      decision: 'REJECT',
      verdictId: verdict.verdictId,
      liability: verdict.liability,
      violations,
      hint: verdict.liability === 'AGENT_PROVIDER'
        ? 'The agent exceeded its mandate scope. Check constraints.'
        : verdict.liability === 'NONE'
        ? 'The mandate signature is invalid.'
        : 'Unknown rejection reason.',
    };
  }

  async getVerdict(id: number): Promise<Record<string, unknown>> {
    this.recordToolCall('get_verdict', { id });
    const res = await fetch(`${this.baseUrl}/verdicts/${id}`);
    if (!res.ok) {
      return { error: `Verdict ${id} not found` };
    }
    return await res.json() as Record<string, unknown>;
  }
}
