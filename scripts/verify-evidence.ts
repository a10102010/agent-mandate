/**
 * verify-evidence.ts
 *
 * Reads docs/live-test-devnet-2026-11-06.json and verifies:
 *   1. Mandate signature against principal pubkey (Ed25519)
 *   2. Mandate hash matches canonical JSON
 *   3. Verdict PDAs exist on Devnet (where addresses are known)
 *
 * Usage:
 *   npx ts-node scripts/verify-evidence.ts
 *   # or: npx tsx scripts/verify-evidence.ts
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';
import { Connection, PublicKey } from '@solana/web3.js';
import * as ed from '@noble/ed25519';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Canonical JSON: recursively sort keys, no whitespace. */
function canonicalize(obj: unknown): string {
  if (obj === null || obj === undefined) return JSON.stringify(obj);
  if (typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalize).join(',') + ']';
  }
  const sorted = Object.keys(obj as Record<string, unknown>).sort();
  const entries = sorted.map(
    (k) => JSON.stringify(k) + ':' + canonicalize((obj as Record<string, unknown>)[k])
  );
  return '{' + entries.join(',') + '}';
}

function sha256hex(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

function base64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(Buffer.from(b64, 'base64'));
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/** Decode a Base58 Solana pubkey to raw 32 bytes. */
function base58ToBytes(b58: string): Uint8Array {
  return new PublicKey(b58).toBytes();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

interface EvidenceRun {
  run: number;
  mandateId: string;
  mandate: Record<string, unknown>;
  mandateHash: string;
  mandateSignature: string;
  pdas: { mandate: string | null; verdict: string | null };
}

interface Evidence {
  meta: { cluster: string; programId: string };
  participants: { principal: { pubkey: string } };
  runs: EvidenceRun[];
}

async function main() {
  const evidencePath = join(__dirname, '..', 'docs', 'live-test-devnet-2026-11-06.json');
  const evidence: Evidence = JSON.parse(readFileSync(evidencePath, 'utf8'));

  const principalPubkey = evidence.participants.principal.pubkey;
  const principalBytes = base58ToBytes(principalPubkey);

  console.log(`Cluster:    ${evidence.meta.cluster}`);
  console.log(`Program:    ${evidence.meta.programId}`);
  console.log(`Principal:  ${principalPubkey}`);
  console.log('');

  const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
  let allOk = true;

  for (const run of evidence.runs) {
    console.log(`--- Run ${run.run}: ${run.mandateId} ---`);

    // 1. Verify mandate hash
    const canonical = canonicalize(run.mandate);
    const computedHash = sha256hex(canonical);
    const hashOk = computedHash === run.mandateHash;
    console.log(`  Mandate hash:      ${hashOk ? 'OK' : 'FAIL'} (computed ${computedHash.slice(0, 16)}...)`);
    if (!hashOk) allOk = false;

    // 2. Verify mandate signature (Ed25519)
    const sigBytes = base64ToBytes(run.mandateSignature);
    const msgBytes = new TextEncoder().encode(canonical);
    let sigOk = false;
    try {
      sigOk = await ed.verifyAsync(sigBytes, msgBytes, principalBytes);
    } catch (e) {
      sigOk = false;
    }
    console.log(`  Mandate signature: ${sigOk ? 'OK' : 'FAIL'}`);
    if (!sigOk) allOk = false;

    // 3. Check verdict PDA on-chain (if address known)
    if (run.pdas.verdict) {
      try {
        const verdictKey = new PublicKey(run.pdas.verdict);
        const info = await connection.getAccountInfo(verdictKey);
        const pdaOk = info !== null;
        console.log(`  Verdict PDA:       ${pdaOk ? 'OK' : 'FAIL'} (${run.pdas.verdict.slice(0, 8)}...)`);
        if (!pdaOk) allOk = false;
      } catch (e) {
        console.log(`  Verdict PDA:       FAIL (fetch error: ${e})`);
        allOk = false;
      }
    } else {
      console.log(`  Verdict PDA:       SKIP (address not recorded)`);
    }

    // 4. Check mandate PDA on-chain (if address known)
    if (run.pdas.mandate) {
      try {
        const mandateKey = new PublicKey(run.pdas.mandate);
        const info = await connection.getAccountInfo(mandateKey);
        const pdaOk = info !== null;
        console.log(`  Mandate PDA:       ${pdaOk ? 'OK' : 'FAIL'} (${run.pdas.mandate.slice(0, 8)}...)`);
        if (!pdaOk) allOk = false;
      } catch (e) {
        console.log(`  Mandate PDA:       FAIL (fetch error: ${e})`);
        allOk = false;
      }
    } else {
      console.log(`  Mandate PDA:       SKIP (address not recorded)`);
    }

    console.log('');
  }

  console.log(allOk ? 'ALL CHECKS PASSED' : 'SOME CHECKS FAILED');
  process.exit(allOk ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
