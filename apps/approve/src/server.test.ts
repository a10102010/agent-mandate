import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateEd25519KeyPair, verifyMandateSignature } from 'agent-mandate-sdk';
import { decodeMandateRequest, encodeMandateRequest, app, setPrincipalKey } from './server.js';

describe('approve: decodeMandateRequest', () => {
  it('decodes a valid base64url mandate request', () => {
    const req = {
      mandateId: 'test-001',
      agent: { id: 'agent-1', scheme: 'ed25519' as const, pubkey: 'fakepubkey' },
      constraints: { currency: 'EUR', maxTotal: 10000, merchants: ['shop-a'] },
      validHours: 24,
    };
    const b64 = encodeMandateRequest(req);
    const decoded = decodeMandateRequest(b64);
    assert.equal(decoded.mandateId, 'test-001');
    assert.equal(decoded.agent.id, 'agent-1');
    assert.equal(decoded.constraints.maxTotal, 10000);
  });

  it('rejects missing required fields', () => {
    const bad = Buffer.from(JSON.stringify({ mandateId: 'x' })).toString('base64url');
    assert.throws(() => decodeMandateRequest(bad), /missing required fields/);
  });
});

describe('approve: POST /approve signs mandate', () => {
  it('signs and returns a valid mandate', async () => {
    const principalKp = generateEd25519KeyPair();
    const agentKp = generateEd25519KeyPair();
    setPrincipalKey(principalKp);

    const req = {
      mandateId: 'sig-test-001',
      agent: { id: 'test-agent', scheme: 'ed25519' as const, pubkey: agentKp.pubkey },
      constraints: { currency: 'USD', maxTotal: 5000, categories: ['api-credits'], merchants: ['north7.ai'] },
      validHours: 1,
    };
    const b64 = encodeMandateRequest(req);

    // Simulate POST using the Express app
    const { default: http } = await import('node:http');
    const server = app.listen(0);
    const port = (server.address() as any).port;

    try {
      const res = await fetch(`http://127.0.0.1:${port}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ req: b64 }),
      });
      const data = await res.json() as any;

      assert.ok(data.signedMandate, 'should have signedMandate');
      assert.equal(data.signedMandate.mandate.mandateId, 'sig-test-001');
      assert.equal(data.signedMandate.mandate.agent.id, 'test-agent');
      assert.equal(data.signedMandate.mandate.constraints.maxTotal, 5000);
      assert.ok(data.signedMandate.signature, 'should have signature');
      assert.ok(data.signedMandate.mandateHash, 'should have mandateHash');

      // Verify signature is valid
      const valid = await verifyMandateSignature(data.signedMandate);
      assert.ok(valid, 'mandate signature should be valid');
    } finally {
      server.close();
    }
  });
});
