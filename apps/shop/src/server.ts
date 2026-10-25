/**
 * Demo Shop — sells API credits under mandate.
 *
 * GET  /catalog     — product list
 * POST /cart        — sign a cart (merchant signs with signCart)
 * POST /pay         — behind verifier middleware, delivers credit receipt on APPROVE
 */

import express from 'express';
import {
  generateEd25519KeyPair,
  signCart,
  type Order,
  type KeyPair,
} from 'agent-mandate-sdk';

const app = express();
app.use(express.json());

// Merchant key — in production from env/HSM
let merchantKeyPair: KeyPair | null = null;

function getMerchantKey(): KeyPair {
  if (!merchantKeyPair) {
    merchantKeyPair = generateEd25519KeyPair();
    console.log(`[shop] Merchant key: ${merchantKeyPair.pubkey}`);
  }
  return merchantKeyPair;
}

export function setMerchantKey(kp: KeyPair): void {
  merchantKeyPair = kp;
}

// Catalog
const CATALOG = [
  { sku: 'credits-1000', name: '1,000 API Credits', unitPrice: 1000, currency: 'USD', category: 'api-credits' },
  { sku: 'credits-5000', name: '5,000 API Credits', unitPrice: 4500, currency: 'USD', category: 'api-credits' },
];

app.get('/catalog', (_req, res) => {
  res.json({ merchant: 'north7.ai', products: CATALOG });
});

/**
 * POST /cart
 * Body: { orderId, items: [{ sku, qty }] }
 * Returns a merchant-signed order.
 */
app.post('/cart', async (req, res) => {
  try {
    const { orderId, items } = req.body as { orderId: string; items: Array<{ sku: string; qty: number }> };
    if (!orderId || !items?.length) {
      return res.status(400).json({ error: 'Missing orderId or items' });
    }

    const orderItems = items.map(i => {
      const product = CATALOG.find(p => p.sku === i.sku);
      if (!product) throw new Error(`Unknown SKU: ${i.sku}`);
      return { sku: product.sku, category: product.category, unitPrice: product.unitPrice, qty: i.qty };
    });

    const total = orderItems.reduce((s, i) => s + i.unitPrice * i.qty, 0);

    const order: Order = {
      orderId,
      merchant: 'north7.ai',
      currency: 'USD',
      items: orderItems,
      total,
      createdAt: Math.floor(Date.now() / 1000),
    };

    const signedOrder = await signCart(order, getMerchantKey());
    res.json({ signedOrder });
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/**
 * POST /pay
 * Protected by verifier middleware in production.
 * When reached, req.verdict exists (APPROVE).
 * Returns a credit receipt.
 */
app.post('/pay', (req, res) => {
  const verdict = (req as any).verdict;
  if (!verdict) {
    // Standalone mode without middleware — for testing
    return res.status(402).json({ error: 'No mandate verification — use verifier middleware' });
  }

  res.json({
    receipt: {
      status: 'CREDITED',
      mandateHash: verdict.mandateHash,
      orderHash: verdict.orderHash,
      remainingBudget: verdict.remainingBudget,
      creditedAt: new Date().toISOString(),
    },
  });
});

/** Merchant pubkey for agents to verify cart signatures */
app.get('/merchant/pubkey', (_req, res) => {
  res.json({ scheme: getMerchantKey().scheme, pubkey: getMerchantKey().pubkey });
});

export { app, getMerchantKey };

const PORT = parseInt(process.env.PORT ?? '3300');

if (process.argv[1]?.includes('server')) {
  app.listen(PORT, () => {
    console.log(`[shop] Credit shop on :${PORT}`);
    console.log(`[shop] Merchant pubkey: ${getMerchantKey().pubkey}`);
  });
}
