/**
 * Canonical JSON serialization.
 * Rules:
 * - Keys recursively sorted alphabetically
 * - No whitespace
 * - Only safe integers (Number.isSafeInteger)
 * - Undefined fields omitted (standard JSON behavior)
 */

import { createHash } from 'node:crypto';

export function canonicalize(obj: unknown): string {
  return JSON.stringify(sortKeys(obj));
}

function sortKeys(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) && !Number.isFinite(value)) {
      throw new Error(`Unsafe number in canonical JSON: ${value}`);
    }
    return value;
  }

  if (typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }

  if (typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    const keys = Object.keys(value as Record<string, unknown>).sort();
    for (const key of keys) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) {
        sorted[key] = sortKeys(v);
      }
    }
    return sorted;
  }

  return value;
}

export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

export function sha256Hex(data: Uint8Array): string {
  return Buffer.from(sha256(data)).toString('hex');
}

export function hashCanonical(obj: unknown): Uint8Array {
  const canonical = canonicalize(obj);
  const bytes = new TextEncoder().encode(canonical);
  return sha256(bytes);
}

export function hashCanonicalHex(obj: unknown): string {
  return Buffer.from(hashCanonical(obj)).toString('hex');
}
