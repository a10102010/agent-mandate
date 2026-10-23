import type { Scheme } from './crypto.js';

// ── Mandate ──

export interface Principal {
  scheme: Scheme;
  pubkey: string; // base58
}

export interface Agent {
  id: string;
  scheme: Scheme;
  pubkey: string; // base58
}

export interface Constraints {
  currency: string;
  maxTotal: number; // minor units
  maxPerOrder?: number;
  maxPerItem?: number;
  maxQuantity?: number;
  maxOrders?: number;
  categories?: string[];
  merchants?: string[];
  skus?: string[];
}

export interface Policy {
  liabilityModel: 'mandate-scope-v1';
  disputeWindowSec: number;
}

export interface Mandate {
  version: '1';
  mandateId: string;
  principal: Principal;
  agent: Agent;
  constraints: Constraints;
  validFrom: number;  // unix seconds
  validUntil: number; // unix seconds
  nonce: string;      // >= 16 chars
  policy: Policy;
}

export interface SignedMandate {
  mandate: Mandate;
  signature: string;    // base58
  mandateHash: string;  // hex
}

// ── Order ──

export interface OrderItem {
  sku: string;
  category: string;
  unitPrice: number; // minor units
  qty: number;
}

export interface Order {
  orderId: string;
  merchant: string;
  currency: string;
  items: OrderItem[];
  total: number; // must equal sum of unitPrice * qty
  createdAt: number; // unix seconds
}

export interface SignedOrder extends Order {
  merchantPubkey: string;  // base58
  cartSignature: string;   // base58
}

// ── Attestation ──

export interface Attestation {
  version: '1';
  agentId: string;
  agentPubkey: string;  // base58
  modelVersion: string;
  mandateHash: string;  // hex
  orderHash: string;    // hex
  cartHash: string;     // hex
  traceHash: string;    // hex (sha256 over prompt/transcript)
  timestamp: number;    // unix seconds
}

export interface SignedAttestation {
  attestation: Attestation;
  signature: string;       // base58
  attestationHash: string; // hex
}

// ── Verifier ──

export type Decision = 'APPROVE' | 'REJECT';
export type Liability = 'PRINCIPAL' | 'AGENT_PROVIDER' | 'NONE';

export type ViolationCode =
  | 'MANDATE_SIG_INVALID'
  | 'ATTESTATION_SIG_INVALID'
  | 'ATTESTATION_AGENT_MISMATCH'
  | 'ATTESTATION_HASH_MISMATCH'
  | 'CART_SIG_INVALID'
  | 'ATTESTATION_REPLAYED'
  | 'MANDATE_EXPIRED'
  | 'MANDATE_NOT_YET_VALID'
  | 'ORDER_TOTAL_MISMATCH'
  | 'CURRENCY_MISMATCH'
  | 'MERCHANT_NOT_ALLOWED'
  | 'CATEGORY_NOT_ALLOWED'
  | 'SKU_NOT_ALLOWED'
  | 'QTY_EXCEEDED'
  | 'ITEM_PRICE_EXCEEDED'
  | 'ORDER_LIMIT_EXCEEDED'
  | 'BUDGET_EXCEEDED'
  | 'ORDER_COUNT_EXCEEDED';

export interface Violation {
  code: ViolationCode;
  detail: string;
}

export interface VerifierState {
  spent: number;  // minor units already spent
  orders: number; // orders already processed
}

export interface VerifyResult {
  decision: Decision;
  liability: Liability;
  violations: Violation[];
  mandateHash: string;
  orderHash: string;
  attestationHash: string;
  remainingBudget: number;
}
