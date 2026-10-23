import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateEd25519KeyPair,
  generateEs256KeyPair,
  signEd25519,
  verifyEd25519,
  signEs256,
  verifyEs256,
  pubkeyFromBase58,
  pubkeyToBase58,
  signatureToBase58,
  signatureFromBase58,
  ATTESTATION_PREFIX,
  CART_PREFIX,
  prefixMessage,
} from './crypto.js';

describe('ed25519', () => {
  it('generates a key pair', () => {
    const kp = generateEd25519KeyPair();
    assert.equal(kp.scheme, 'ed25519');
    assert.equal(kp.publicKey.length, 32);
    assert.equal(kp.secretKey.length, 64);
    assert.ok(kp.pubkey.length > 0);
  });

  it('signs and verifies', () => {
    const kp = generateEd25519KeyPair();
    const message = new TextEncoder().encode('test message');
    const sig = signEd25519(message, kp.secretKey);
    assert.ok(verifyEd25519(message, sig, kp.publicKey));
  });

  it('rejects tampered message', () => {
    const kp = generateEd25519KeyPair();
    const message = new TextEncoder().encode('test message');
    const sig = signEd25519(message, kp.secretKey);
    const tampered = new TextEncoder().encode('tampered message');
    assert.ok(!verifyEd25519(tampered, sig, kp.publicKey));
  });

  it('rejects wrong key', () => {
    const kp1 = generateEd25519KeyPair();
    const kp2 = generateEd25519KeyPair();
    const message = new TextEncoder().encode('test');
    const sig = signEd25519(message, kp1.secretKey);
    assert.ok(!verifyEd25519(message, sig, kp2.publicKey));
  });
});

describe('es256', () => {
  it('generates a key pair', async () => {
    const kp = await generateEs256KeyPair();
    assert.equal(kp.scheme, 'es256');
    assert.equal(kp.publicKey.length, 65); // uncompressed P-256 point
    assert.ok(kp.secretKey.length > 0);
    assert.ok(kp.pubkey.length > 0);
  });

  it('signs and verifies', async () => {
    const kp = await generateEs256KeyPair();
    const message = new TextEncoder().encode('test message');
    const sig = await signEs256(message, kp.secretKey);
    assert.ok(await verifyEs256(message, sig, kp.publicKey));
  });

  it('rejects tampered message', async () => {
    const kp = await generateEs256KeyPair();
    const message = new TextEncoder().encode('test message');
    const sig = await signEs256(message, kp.secretKey);
    const tampered = new TextEncoder().encode('tampered message');
    assert.ok(!(await verifyEs256(tampered, sig, kp.publicKey)));
  });
});

describe('domain separation prefixes', () => {
  it('ATTESTATION_PREFIX matches on-chain constant', () => {
    assert.deepEqual(
      ATTESTATION_PREFIX,
      new TextEncoder().encode('mandate-clearing/attestation/v1')
    );
  });

  it('CART_PREFIX matches on-chain constant', () => {
    assert.deepEqual(
      CART_PREFIX,
      new TextEncoder().encode('mandate-clearing/cart/v1')
    );
  });

  it('prefixMessage prepends prefix correctly', () => {
    const msg = new Uint8Array([1, 2, 3]);
    const prefixed = prefixMessage(ATTESTATION_PREFIX, msg);
    assert.equal(prefixed.length, ATTESTATION_PREFIX.length + 3);
    assert.deepEqual(prefixed.slice(0, ATTESTATION_PREFIX.length), ATTESTATION_PREFIX);
    assert.deepEqual(prefixed.slice(ATTESTATION_PREFIX.length), msg);
  });

  it('different prefixes produce different signed messages', () => {
    const kp = generateEd25519KeyPair();
    const payload = new TextEncoder().encode('same-payload');

    const attMsg = prefixMessage(ATTESTATION_PREFIX, payload);
    const cartMsg = prefixMessage(CART_PREFIX, payload);

    const sigAtt = signEd25519(attMsg, kp.secretKey);
    const sigCart = signEd25519(cartMsg, kp.secretKey);

    // Attestation sig does NOT verify against cart-prefixed message
    assert.ok(!verifyEd25519(cartMsg, sigAtt, kp.publicKey));
    // Cart sig does NOT verify against attestation-prefixed message
    assert.ok(!verifyEd25519(attMsg, sigCart, kp.publicKey));
    // Each verifies against its own prefix
    assert.ok(verifyEd25519(attMsg, sigAtt, kp.publicKey));
    assert.ok(verifyEd25519(cartMsg, sigCart, kp.publicKey));
  });
});

describe('base58 encoding', () => {
  it('roundtrips pubkey', () => {
    const kp = generateEd25519KeyPair();
    const encoded = pubkeyToBase58(kp.publicKey);
    const decoded = pubkeyFromBase58(encoded);
    assert.deepEqual(decoded, kp.publicKey);
  });

  it('roundtrips signature', () => {
    const kp = generateEd25519KeyPair();
    const sig = signEd25519(new TextEncoder().encode('test'), kp.secretKey);
    const encoded = signatureToBase58(sig);
    const decoded = signatureFromBase58(encoded);
    assert.deepEqual(decoded, sig);
  });
});
