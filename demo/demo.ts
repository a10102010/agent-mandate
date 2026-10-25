/**
 * Demo: full mandate lifecycle
 * Principal issues mandate → Merchant signs cart → Agent attests → Verifier approves
 */

import { generateEd25519KeyPair } from './crypto.js';
import { issueMandate, signCart, attestOrder } from './mandate.js';
import { verifyOrder } from './verifier.js';
import { InMemoryNonceRegistry } from './nonce.js';
import { hashCanonicalHex } from './canonical.js';
import type { Mandate, Order, VerifierState } from './types.js';

async function main() {
  console.log('=== Agent Mandate Demo ===\n');

  // Generate keys
  const principalKp = generateEd25519KeyPair();
  const agentKp = generateEd25519KeyPair();
  const merchantKp = generateEd25519KeyPair();

  console.log(`Principal pubkey: ${principalKp.pubkey}`);
  console.log(`Agent pubkey:     ${agentKp.pubkey}`);
  console.log(`Merchant pubkey:  ${merchantKp.pubkey}\n`);

  // 1. Principal issues mandate
  const now = Math.floor(Date.now() / 1000);
  const mandateData: Omit<Mandate, 'version' | 'nonce'> = {
    mandateId: 'demo-mandate-001',
    principal: { scheme: 'ed25519', pubkey: principalKp.pubkey },
    agent: { id: 'demo-agent', scheme: 'ed25519', pubkey: agentKp.pubkey },
    constraints: {
      currency: 'EUR',
      maxTotal: 50000, // 500.00 EUR
      maxPerOrder: 20000,
      maxQuantity: 5,
      categories: ['books', 'electronics'],
      merchants: ['demo-shop'],
    },
    validFrom: now - 3600,
    validUntil: now + 86400,
    policy: { liabilityModel: 'mandate-scope-v1', disputeWindowSec: 604800 },
  };

  const signedMandate = await issueMandate({ mandate: mandateData, principalKeyPair: principalKp });
  console.log(`Mandate issued: ${signedMandate.mandateHash}`);
  console.log(`Mandate signature: ${signedMandate.signature.slice(0, 20)}...\n`);

  // 2. Create and sign an order (merchant)
  const order: Order = {
    orderId: 'order-001',
    merchant: 'demo-shop',
    currency: 'EUR',
    items: [
      { sku: 'BOOK-42', category: 'books', unitPrice: 1999, qty: 2 },
    ],
    total: 3998,
    createdAt: now,
  };

  const signedOrder = await signCart(order, merchantKp);
  console.log(`Cart signed by merchant: ${signedOrder.cartSignature.slice(0, 20)}...\n`);

  // 3. Agent attests the order
  const traceHash = hashCanonicalHex({ prompt: 'Buy 2 copies of book 42', response: 'Purchasing...' });

  const signedAttestation = await attestOrder({
    agentKeyPair: agentKp,
    agentId: 'demo-agent',
    modelVersion: 'claude-opus-4-20250514',
    mandateHash: signedMandate.mandateHash,
    order,
    traceHash,
    timestamp: now,
  });
  console.log(`Attestation hash: ${signedAttestation.attestationHash}`);
  console.log(`Attestation signature: ${signedAttestation.signature.slice(0, 20)}...\n`);

  // 4. Verifier checks everything
  const state: VerifierState = { spent: 0, orders: 0 };
  const nonceRegistry = new InMemoryNonceRegistry();

  const result = verifyOrder({
    signedMandate,
    order: signedOrder,
    signedAttestation,
    state,
    nonceRegistry,
    now,
  });

  console.log('=== Verification Result ===');
  console.log(`Decision:         ${result.decision}`);
  console.log(`Liability:        ${result.liability}`);
  console.log(`Remaining Budget: ${result.remainingBudget} (${(result.remainingBudget / 100).toFixed(2)} EUR)`);
  console.log(`Violations:       ${result.violations.length === 0 ? 'none' : result.violations.map(v => v.code).join(', ')}`);

  // 5. Try replay → should reject
  console.log('\n=== Replay Attempt ===');
  const replayResult = verifyOrder({
    signedMandate,
    order: signedOrder,
    signedAttestation,
    state: { spent: state.spent + order.total, orders: state.orders + 1 },
    nonceRegistry,
    now,
  });
  console.log(`Decision: ${replayResult.decision}`);
  console.log(`Violations: ${replayResult.violations.map(v => v.code).join(', ')}`);
}

main().catch(console.error);
