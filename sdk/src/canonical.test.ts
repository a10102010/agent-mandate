import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize, sha256, sha256Hex, hashCanonical, hashCanonicalHex } from './canonical.js';

describe('canonicalize', () => {
  it('sorts keys alphabetically', () => {
    const result = canonicalize({ z: 1, a: 2, m: 3 });
    assert.equal(result, '{"a":2,"m":3,"z":1}');
  });

  it('sorts keys recursively', () => {
    const result = canonicalize({ b: { z: 1, a: 2 }, a: 1 });
    assert.equal(result, '{"a":1,"b":{"a":2,"z":1}}');
  });

  it('key-order independence: same output regardless of input order', () => {
    const a = canonicalize({ x: 1, y: 2, z: 3 });
    const b = canonicalize({ z: 3, x: 1, y: 2 });
    const c = canonicalize({ y: 2, z: 3, x: 1 });
    assert.equal(a, b);
    assert.equal(b, c);
  });

  it('omits undefined fields', () => {
    const result = canonicalize({ a: 1, b: undefined, c: 3 });
    assert.equal(result, '{"a":1,"c":3}');
  });

  it('no whitespace', () => {
    const result = canonicalize({ hello: 'world', nested: { key: 'value' } });
    assert.ok(!result.includes(' '));
    assert.ok(!result.includes('\n'));
    assert.ok(!result.includes('\t'));
  });

  it('handles arrays', () => {
    const result = canonicalize({ items: [3, 1, 2] });
    assert.equal(result, '{"items":[3,1,2]}');
  });

  it('handles nested arrays with objects', () => {
    const result = canonicalize({ items: [{ b: 2, a: 1 }] });
    assert.equal(result, '{"items":[{"a":1,"b":2}]}');
  });

  it('handles null', () => {
    const result = canonicalize({ a: null });
    assert.equal(result, '{"a":null}');
  });

  it('handles booleans', () => {
    const result = canonicalize({ t: true, f: false });
    assert.equal(result, '{"f":false,"t":true}');
  });

  it('handles empty object', () => {
    assert.equal(canonicalize({}), '{}');
  });

  it('handles empty array', () => {
    assert.equal(canonicalize([]), '[]');
  });
});

describe('sha256', () => {
  it('produces consistent hashes', () => {
    const data = new TextEncoder().encode('hello');
    const h1 = sha256Hex(data);
    const h2 = sha256Hex(data);
    assert.equal(h1, h2);
    assert.equal(h1.length, 64); // 32 bytes = 64 hex chars
  });
});

describe('hashCanonical', () => {
  it('produces same hash for differently ordered keys', () => {
    const h1 = hashCanonicalHex({ z: 1, a: 2 });
    const h2 = hashCanonicalHex({ a: 2, z: 1 });
    assert.equal(h1, h2);
  });

  it('produces different hashes for different values', () => {
    const h1 = hashCanonicalHex({ a: 1 });
    const h2 = hashCanonicalHex({ a: 2 });
    assert.notEqual(h1, h2);
  });
});
