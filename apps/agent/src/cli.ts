#!/usr/bin/env node
/**
 * Reference Agent CLI for Mandate Clearing.
 *
 * agent mandate --merchant north7.ai --categories api-credits --max-total 10000 --hours 24
 * agent buy --sku credits-1000 --qty 2
 * agent buy --evil  (out-of-scope order, must get 402)
 */

import {
  generateEd25519KeyPair,
  attestOrder,
  hashCanonicalHex,
  type KeyPair,
  type SignedMandate,
  type Order,
} from 'agent-mandate-sdk';

// Agent key — persistent across commands in a real agent
const agentKeyPair: KeyPair = generateEd25519KeyPair();
let storedMandate: SignedMandate | null = null;

const APPROVE_URL = process.env.APPROVE_URL ?? 'http://localhost:3100';
const SHOP_URL = process.env.SHOP_URL ?? 'http://localhost:3300';
const VERIFIER_URL = process.env.VERIFIER_URL ?? 'http://localhost:3200';

export { agentKeyPair, storedMandate };

export function setStoredMandate(m: SignedMandate): void {
  storedMandate = m;
}

/**
 * Request a mandate from the principal via the approval service.
 */
export async function requestMandate(opts: {
  merchant: string;
  categories: string[];
  maxTotal: number;
  maxPerOrder?: number;
  hours: number;
}): Promise<SignedMandate> {
  const mandateReq = {
    mandateId: `mnd-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    agent: { id: 'reference-agent', scheme: 'ed25519' as const, pubkey: agentKeyPair.pubkey },
    constraints: {
      currency: 'USD',
      maxTotal: opts.maxTotal,
      maxPerOrder: opts.maxPerOrder,
      categories: opts.categories,
      merchants: [opts.merchant],
    },
    validHours: opts.hours,
  };

  const b64 = Buffer.from(JSON.stringify(mandateReq)).toString('base64url');

  // POST to approval service (auto-approve for CLI flow)
  const res = await fetch(`${APPROVE_URL}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ req: b64 }),
  });

  if (!res.ok) {
    const err = await res.json() as any;
    throw new Error(`Mandate rejected: ${err.error}`);
  }

  const data = await res.json() as any;
  storedMandate = data.signedMandate;
  console.log(`[agent] Mandate approved: ${storedMandate!.mandate.mandateId}`);
  console.log(`[agent] Budget: ${storedMandate!.mandate.constraints.maxTotal / 100} ${storedMandate!.mandate.constraints.currency}`);
  return storedMandate!;
}

/**
 * Buy items from the shop.
 */
export async function buy(opts: {
  sku: string;
  qty: number;
  evil?: boolean;
}): Promise<{ status: number; body: Record<string, unknown> }> {
  if (!storedMandate) throw new Error('No mandate — run `agent mandate` first');

  const orderId = `ord-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  // Get signed cart from shop
  const cartRes = await fetch(`${SHOP_URL}/cart`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ orderId, items: [{ sku: opts.sku, qty: opts.qty }] }),
  });

  if (!cartRes.ok) {
    const err = await cartRes.json() as any;
    throw new Error(`Cart failed: ${err.error}`);
  }

  const { signedOrder } = await cartRes.json() as any;

  // Evil mode: tamper with the merchant field
  if (opts.evil) {
    signedOrder.merchant = 'evil-shop.darkweb.io';
    console.log('[agent] EVIL MODE: changed merchant to evil-shop.darkweb.io');
  }

  // Build trace hash from CLI input
  const traceInput = `buy --sku ${opts.sku} --qty ${opts.qty}${opts.evil ? ' --evil' : ''}`;
  const traceHash = hashCanonicalHex({ input: traceInput, timestamp: Date.now() });

  // Attest
  const plainOrder: Order = {
    orderId: signedOrder.orderId,
    merchant: signedOrder.merchant,
    currency: signedOrder.currency,
    items: signedOrder.items,
    total: signedOrder.total,
    createdAt: signedOrder.createdAt,
  };

  const signedAttestation = await attestOrder({
    agentKeyPair,
    agentId: 'reference-agent',
    modelVersion: 'cli-v0.1',
    mandateHash: storedMandate.mandateHash,
    order: plainOrder,
    traceHash,
    timestamp: Math.floor(Date.now() / 1000),
  });

  // Send to verifier
  const verifyRes = await fetch(`${VERIFIER_URL}/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      signedMandate: storedMandate,
      signedOrder,
      signedAttestation,
    }),
  });

  const verdict = await verifyRes.json() as Record<string, unknown>;

  console.log(`[agent] Verdict: ${verdict.decision} | Liability: ${verdict.liability}`);
  if (verdict.decision === 'APPROVE') {
    console.log(`[agent] Remaining budget: ${(verdict.remainingBudget as number) / 100} USD`);
  } else {
    console.log(`[agent] Violations: ${JSON.stringify(verdict.violations)}`);
  }

  return { status: verifyRes.status, body: verdict };
}

// CLI entry point
if (process.argv[1]?.includes('cli')) {
  const args = process.argv.slice(2);
  const cmd = args[0];

  if (cmd === 'mandate') {
    const merchant = args.find((_, i) => args[i - 1] === '--merchant') ?? 'north7.ai';
    const categories = (args.find((_, i) => args[i - 1] === '--categories') ?? 'api-credits').split(',');
    const maxTotal = parseInt(args.find((_, i) => args[i - 1] === '--max-total') ?? '10000');
    const hours = parseInt(args.find((_, i) => args[i - 1] === '--hours') ?? '24');
    await requestMandate({ merchant, categories, maxTotal, hours });
  } else if (cmd === 'buy') {
    const sku = args.find((_, i) => args[i - 1] === '--sku') ?? 'credits-1000';
    const qty = parseInt(args.find((_, i) => args[i - 1] === '--qty') ?? '1');
    const evil = args.includes('--evil');
    await buy({ sku, qty, evil });
  } else {
    console.log('Usage: agent mandate|buy [options]');
  }
}
