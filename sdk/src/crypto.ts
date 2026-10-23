/**
 * Cryptographic operations for agent-mandate.
 * Supports two schemes:
 * - "ed25519" via tweetnacl
 * - "es256" via WebCrypto P-256 (for Passkeys)
 */

import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { webcrypto } from 'node:crypto';

export type Scheme = 'ed25519' | 'es256';

export interface KeyPair {
  scheme: Scheme;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  /** Base58-encoded public key */
  pubkey: string;
}

// ── Ed25519 ──

export function generateEd25519KeyPair(): KeyPair {
  const kp = nacl.sign.keyPair();
  return {
    scheme: 'ed25519',
    publicKey: kp.publicKey,
    secretKey: kp.secretKey,
    pubkey: bs58.encode(kp.publicKey),
  };
}

export function signEd25519(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return nacl.sign.detached(message, secretKey);
}

export function verifyEd25519(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  return nacl.sign.detached.verify(message, signature, publicKey);
}

// ── ES256 (P-256 / WebCrypto) ──

const subtle = webcrypto.subtle;

export async function generateEs256KeyPair(): Promise<KeyPair> {
  const cryptoKp = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );

  const rawPub = new Uint8Array(await subtle.exportKey('raw', cryptoKp.publicKey));
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', cryptoKp.privateKey));

  return {
    scheme: 'es256',
    publicKey: rawPub,
    secretKey: pkcs8,
    pubkey: bs58.encode(rawPub),
  };
}

export async function signEs256(message: Uint8Array, secretKeyPkcs8: Uint8Array): Promise<Uint8Array> {
  const key = await subtle.importKey(
    'pkcs8',
    secretKeyPkcs8,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
  const sig = await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    message,
  );
  return new Uint8Array(sig);
}

export async function verifyEs256(message: Uint8Array, signature: Uint8Array, publicKeyRaw: Uint8Array): Promise<boolean> {
  const key = await subtle.importKey(
    'raw',
    publicKeyRaw,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
  return subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    signature,
    message,
  );
}

// ── Unified sign / verify ──

export function sign(scheme: Scheme, message: Uint8Array, secretKey: Uint8Array): Uint8Array | Promise<Uint8Array> {
  if (scheme === 'ed25519') {
    return signEd25519(message, secretKey);
  }
  return signEs256(message, secretKey);
}

export function verify(scheme: Scheme, message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean | Promise<boolean> {
  if (scheme === 'ed25519') {
    return verifyEd25519(message, signature, publicKey);
  }
  return verifyEs256(message, signature, publicKey);
}

// ── Encoding helpers ──

export function pubkeyFromBase58(b58: string): Uint8Array {
  return bs58.decode(b58);
}

export function pubkeyToBase58(key: Uint8Array): string {
  return bs58.encode(key);
}

export function signatureToBase58(sig: Uint8Array): string {
  return bs58.encode(sig);
}

export function signatureFromBase58(b58: string): Uint8Array {
  return bs58.decode(b58);
}
