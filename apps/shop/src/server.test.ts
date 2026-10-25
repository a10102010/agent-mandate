import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateEd25519KeyPair, verifyCartSignature } from 'agent-mandate-sdk';
import { app, setMerchantKey } from './server.js';

const merchantKp = generateEd25519KeyPair();
setMerchantKey(merchantKp);

let server: ReturnType<typeof app.listen>;
let port: number;

describe('shop', () => {
  it('setup', () => {
    server = app.listen(0);
    port = (server.address() as any).port;
  });

  it('GET /catalog returns products', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/catalog`);
    const data = await res.json() as any;
    assert.equal(data.merchant, 'north7.ai');
    assert.ok(data.products.length >= 2);
    assert.equal(data.products[0].sku, 'credits-1000');
  });

  it('POST /cart returns a signed order with valid signature', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/cart`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ orderId: 'test-ord-1', items: [{ sku: 'credits-1000', qty: 2 }] }),
    });
    const data = await res.json() as any;
    assert.ok(data.signedOrder);
    assert.equal(data.signedOrder.merchant, 'north7.ai');
    assert.equal(data.signedOrder.total, 2000); // 1000 * 2
    assert.ok(data.signedOrder.cartSignature);

    // Verify merchant signature
    const valid = await verifyCartSignature(data.signedOrder);
    assert.ok(valid, 'cart signature should be valid');
  });

  it('POST /pay without middleware returns 402', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/pay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    assert.equal(res.status, 402);
  });

  it('POST /cart rejects unknown SKU', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/cart`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ orderId: 'bad', items: [{ sku: 'nonexistent', qty: 1 }] }),
    });
    assert.equal(res.status, 400);
  });

  it('teardown', () => { server.close(); });
});
