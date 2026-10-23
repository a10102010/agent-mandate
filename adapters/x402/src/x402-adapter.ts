/**
 * x402 Payment Rail Adapter
 *
 * In x402, the client sends a payment payload in the HTTP 402 response flow.
 * This adapter packs the mandate + attestation into that payload and provides
 * a facilitator-side verification function that calls verifyOrder before
 * allowing settlement.
 *
 * The mandate token occupies a single field in the x402 payment payload.
 */

import {
  verifyOrder,
  type SignedMandate,
  type SignedOrder,
  type SignedAttestation,
  type VerifierState,
  type VerifyResult,
  type NonceRegistry,
  InMemoryNonceRegistry,
} from 'agent-mandate-sdk';

// ── x402 Payload Types ──

export interface X402MandatePayload {
  /** The signed mandate from the principal */
  signedMandate: SignedMandate;
  /** The signed order from the merchant */
  signedOrder: SignedOrder;
  /** The agent's attestation */
  signedAttestation: SignedAttestation;
}

export interface X402PaymentRequest {
  /** Standard x402 fields */
  version: string;
  /** The mandate payload — occupies one field in the x402 payment */
  mandatePayload: X402MandatePayload;
  /** Any additional x402 fields the rail requires */
  [key: string]: unknown;
}

// ── Facilitator-Side Verification ──

export interface FacilitatorConfig {
  /** NonceRegistry for replay protection (persistent in production) */
  nonceRegistry: NonceRegistry;
  /** Function to look up current state for a mandate (spent, orders) */
  getState: (mandateId: string) => VerifierState;
  /** Function to update state after approval */
  updateState: (mandateId: string, orderTotal: number) => void;
}

export interface X402VerifyResult extends VerifyResult {
  /** Whether the facilitator should proceed with settlement */
  proceedWithSettlement: boolean;
}

/**
 * Facilitator-side verification of an x402 payment containing a mandate.
 * Calls the pure verifyOrder function, then decides whether to settle.
 *
 * This is the integration point: the verifier is the same everywhere,
 * only the transport (x402, Visa TAP, etc.) differs.
 */
export function verifyX402Payment(
  request: X402PaymentRequest,
  config: FacilitatorConfig,
  now: number,
): X402VerifyResult {
  const { signedMandate, signedOrder, signedAttestation } = request.mandatePayload;

  const state = config.getState(signedMandate.mandate.mandateId);

  const result = verifyOrder({
    signedMandate,
    order: signedOrder,
    signedAttestation,
    state,
    nonceRegistry: config.nonceRegistry,
    now,
  });

  const proceedWithSettlement = result.decision === 'APPROVE';

  // If approved, update state
  if (proceedWithSettlement) {
    config.updateState(signedMandate.mandate.mandateId, signedOrder.total);
  }

  return {
    ...result,
    proceedWithSettlement,
  };
}

/**
 * Helper: create an x402 payment request from mandate components.
 * The agent calls this to build the payment payload.
 */
export function createX402PaymentRequest(
  signedMandate: SignedMandate,
  signedOrder: SignedOrder,
  signedAttestation: SignedAttestation,
): X402PaymentRequest {
  return {
    version: 'x402-mandate-v1',
    mandatePayload: {
      signedMandate,
      signedOrder,
      signedAttestation,
    },
  };
}

/**
 * Helper: create a simple in-memory facilitator config for testing.
 */
export function createTestFacilitatorConfig(): FacilitatorConfig {
  const states = new Map<string, VerifierState>();

  return {
    nonceRegistry: new InMemoryNonceRegistry(),
    getState(mandateId: string): VerifierState {
      return states.get(mandateId) ?? { spent: 0, orders: 0 };
    },
    updateState(mandateId: string, orderTotal: number): void {
      const current = states.get(mandateId) ?? { spent: 0, orders: 0 };
      states.set(mandateId, {
        spent: current.spent + orderTotal,
        orders: current.orders + 1,
      });
    },
  };
}
