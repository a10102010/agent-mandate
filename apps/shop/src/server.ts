/**
 * Demo Shop — sells API credits under mandate.
 *
 * GET  /catalog     — product list
 * POST /cart        — sign a cart (merchant signs with signCart)
 * POST /pay         — behind verifier middleware, delivers credit receipt on APPROVE
 *                     Idempotent: attestationHash prevents double-credit
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

// Credit fulfillment tracking (idempotent by attestationHash)
const fulfilledOrders = new Map<string, { creditedAt: string; verdictId?: number }>();

// N7 API config for real credit fulfillment
const N7_API_URL = process.env.N7_API_URL ?? '';
const N7_ADMIN_TOKEN = process.env.N7_ADMIN_TOKEN ?? '';
const MOCK_CREDITS = !N7_API_URL || !N7_ADMIN_TOKEN;

const CATALOG = [
  { sku: 'credits-1000', name: '1,000 API Credits', unitPrice: 1000, currency: 'USD', category: 'api-credits', credits: 1000 },
  { sku: 'credits-5000', name: '5,000 API Credits', unitPrice: 4500, currency: 'USD', category: 'api-credits', credits: 5000 },
];

app.get('/catalog', (_req, res) => {
  res.json({ merchant: 'north7.ai', products: CATALOG });
});

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
 * POST /pay — fulfills credit order after mandate verification.
 *
 * When behind verifier middleware: req.verdict exists.
 * Idempotent: if attestationHash already fulfilled, return same receipt.
 */
app.post('/pay', async (req, res) => {
  const verdict = (req as any).verdict;
  if (!verdict) {
    return res.status(402).json({ error: 'No mandate verification — use verifier middleware' });
  }

  const attestationHash = verdict.attestationHash;

  // Idempotent check
  const existing = fulfilledOrders.get(attestationHash);
  if (existing) {
    return res.json({
      receipt: { status: 'ALREADY_CREDITED', ...existing, attestationHash },
    });
  }

  // Calculate total credits from order items
  const order = req.body?.signedOrder ?? {};
  let totalCredits = 0;
  for (const item of (order.items ?? [])) {
    const product = CATALOG.find(p => p.sku === item.sku);
    if (product) totalCredits += product.credits * (item.qty ?? 1);
  }

  // Credit the API key (if real N7 API available)
  let creditResult: any = { mock: true };
  if (!MOCK_CREDITS && totalCredits > 0) {
    try {
      // Need the buyer's API key — passed in X-Buyer-Key header or body
      const buyerKey = req.headers['x-buyer-key'] as string ?? req.body?.buyerApiKey;
      if (buyerKey) {
        const creditRes = await fetch(
          `${N7_API_URL}/v1/admin/credits?api_key=${encodeURIComponent(buyerKey)}&amount=${totalCredits}`,
          {
            method: 'POST',
            headers: { 'X-Admin-Token': N7_ADMIN_TOKEN },
          },
        );
        creditResult = await creditRes.json();
      } else {
        creditResult = { note: 'No buyer API key provided, credits not applied' };
      }
    } catch (err) {
      creditResult = { error: (err as Error).message };
    }
  }

  const receipt = {
    status: 'CREDITED',
    mandateHash: verdict.mandateHash,
    orderHash: verdict.orderHash,
    attestationHash,
    remainingBudget: verdict.remainingBudget,
    totalCredits,
    creditResult,
    creditedAt: new Date().toISOString(),
  };

  fulfilledOrders.set(attestationHash, { creditedAt: receipt.creditedAt, verdictId: (req as any).verdictId });

  res.json({ receipt });
});

app.get('/merchant/pubkey', (_req, res) => {
  res.json({ scheme: getMerchantKey().scheme, pubkey: getMerchantKey().pubkey });
});

export { app, getMerchantKey };

const PORT = parseInt(process.env.PORT ?? '3300');

if (process.argv[1] === new URL(import.meta.url).pathname) {
  app.listen(PORT, () => console.log(`[shop] on :${PORT}`));
}
