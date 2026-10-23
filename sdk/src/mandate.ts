/**
 * Core mandate operations:
 * - issueMandate: Principal signs a mandate
 * - attestOrder: Agent attests an order
 * - signCart: Merchant signs the cart
 * - Signature verification helpers
 */

import { canonicalize, hashCanonical, hashCanonicalHex } from './canonical.js';
import {
  type KeyPair,
  type Scheme,
  sign,
  verify,
  signatureToBase58,
  signatureFromBase58,
  pubkeyFromBase58,
} from './crypto.js';
import type {
  Mandate,
  SignedMandate,
  Order,
  SignedOrder,
  Attestation,
  SignedAttestation,
} from './types.js';
import { randomBytes } from 'node:crypto';

// ── Issue Mandate ──

export interface IssueMandateInput {
  mandate: Omit<Mandate, 'version' | 'nonce'> & { nonce?: string };
  principalKeyPair: KeyPair;
}

export async function issueMandate(input: IssueMandateInput): Promise<SignedMandate> {
  const nonce = input.mandate.nonce ?? randomBytes(16).toString('hex');

  const mandate: Mandate = {
    ...input.mandate,
    version: '1',
    nonce,
  };

  const canonical = canonicalize(mandate);
  const messageBytes = new TextEncoder().encode(canonical);
  const sig = await sign(input.principalKeyPair.scheme, messageBytes, input.principalKeyPair.secretKey);
  const sigResolved = sig instanceof Promise ? await sig : sig;

  return {
    mandate,
    signature: signatureToBase58(sigResolved),
    mandateHash: hashCanonicalHex(mandate),
  };
}

// ── Verify Mandate Signature ──

export async function verifyMandateSignature(signedMandate: SignedMandate): Promise<boolean> {
  const canonical = canonicalize(signedMandate.mandate);
  const messageBytes = new TextEncoder().encode(canonical);
  const sigBytes = signatureFromBase58(signedMandate.signature);
  const pubBytes = pubkeyFromBase58(signedMandate.mandate.principal.pubkey);

  const result = verify(signedMandate.mandate.principal.scheme, messageBytes, sigBytes, pubBytes);
  return result instanceof Promise ? result : result;
}

// ── Sign Cart (Merchant) ──

export async function signCart(order: Order, merchantKeyPair: KeyPair): Promise<SignedOrder> {
  const canonical = canonicalize(order);
  const messageBytes = new TextEncoder().encode(canonical);
  const sig = await sign(merchantKeyPair.scheme, messageBytes, merchantKeyPair.secretKey);
  const sigResolved = sig instanceof Promise ? await sig : sig;

  return {
    ...order,
    merchantPubkey: merchantKeyPair.pubkey,
    cartSignature: signatureToBase58(sigResolved),
  };
}

// ── Verify Cart Signature ──

export async function verifyCartSignature(signedOrder: SignedOrder): Promise<boolean> {
  // Reconstruct the order without merchantPubkey and cartSignature
  const order: Order = {
    orderId: signedOrder.orderId,
    merchant: signedOrder.merchant,
    currency: signedOrder.currency,
    items: signedOrder.items,
    total: signedOrder.total,
    createdAt: signedOrder.createdAt,
  };

  const canonical = canonicalize(order);
  const messageBytes = new TextEncoder().encode(canonical);
  const sigBytes = signatureFromBase58(signedOrder.cartSignature);
  const pubBytes = pubkeyFromBase58(signedOrder.merchantPubkey);

  // Detect scheme from key length: 32 bytes = ed25519, 65 bytes = es256
  const scheme: Scheme = pubBytes.length === 32 ? 'ed25519' : 'es256';

  const result = verify(scheme, messageBytes, sigBytes, pubBytes);
  return result instanceof Promise ? result : result;
}

// ── Attest Order (Agent) ──

export interface AttestOrderInput {
  agentKeyPair: KeyPair;
  agentId: string;
  modelVersion: string;
  mandateHash: string;
  order: Order;
  traceHash: string;
  timestamp: number;
}

export async function attestOrder(input: AttestOrderInput): Promise<SignedAttestation> {
  const orderHash = hashCanonicalHex(input.order);

  // Cart hash = hash of the order (same as orderHash since the order is the cart content)
  const cartHash = orderHash;

  const attestation: Attestation = {
    version: '1',
    agentId: input.agentId,
    agentPubkey: input.agentKeyPair.pubkey,
    modelVersion: input.modelVersion,
    mandateHash: input.mandateHash,
    orderHash,
    cartHash,
    traceHash: input.traceHash,
    timestamp: input.timestamp,
  };

  const canonical = canonicalize(attestation);
  const messageBytes = new TextEncoder().encode(canonical);
  const sig = await sign(input.agentKeyPair.scheme, messageBytes, input.agentKeyPair.secretKey);
  const sigResolved = sig instanceof Promise ? await sig : sig;

  return {
    attestation,
    signature: signatureToBase58(sigResolved),
    attestationHash: hashCanonicalHex(attestation),
  };
}

// ── Verify Attestation Signature ──

export async function verifyAttestationSignature(signedAttestation: SignedAttestation): Promise<boolean> {
  const canonical = canonicalize(signedAttestation.attestation);
  const messageBytes = new TextEncoder().encode(canonical);
  const sigBytes = signatureFromBase58(signedAttestation.signature);
  const pubBytes = pubkeyFromBase58(signedAttestation.attestation.agentPubkey);

  // Detect scheme from key length
  const scheme: Scheme = pubBytes.length === 32 ? 'ed25519' : 'es256';

  const result = verify(scheme, messageBytes, sigBytes, pubBytes);
  return result instanceof Promise ? result : result;
}
