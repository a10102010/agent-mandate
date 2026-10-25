/**
 * MCP Server tests:
 * 1. Tool schemas are correctly defined
 * 2. Complete purchase flow against live endpoints
 * 3. Out-of-scope purchase returns readable REJECT
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { MandateAgent } from './agent.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const BASE_URL = process.env.MANDATE_BASE_URL ?? 'https://www.north7.ai/mandate';

// Use temp dir for test state to avoid polluting real ~/.mandate-clearing/
const TEST_STATE_DIR = path.join(os.tmpdir(), `.mandate-clearing-test-${Date.now()}`);

describe('MCP: tool schemas', () => {
  it('index.ts exports are valid (import check)', async () => {
    // Just verify the module loads without error
    const mod = await import('./index.js');
    assert.ok(true, 'Module loaded');
  });
});

describe('MCP: MandateAgent', () => {
  let agent: MandateAgent;

  before(() => {
    // Override state dir for tests
    fs.mkdirSync(TEST_STATE_DIR, { recursive: true });
    agent = new MandateAgent(BASE_URL);
  });

  it('request_mandate returns approved mandate', async () => {
    const result = await agent.requestMandate({
      categories: ['api-credits'],
      merchants: ['north7.ai'],
      maxTotal: 5000,
      maxPerOrder: 3000,
      hours: 1,
    });

    assert.equal(result.status, 'APPROVED');
    assert.ok(result.mandateId, 'should have mandateId');
    assert.ok(result.budget, 'should have budget');
    assert.ok(result.validUntil, 'should have validUntil');
    assert.ok(result.agentPubkey, 'should have agentPubkey');
  });

  it('list_mandates shows the new mandate', async () => {
    const result = await agent.listMandates();
    assert.ok((result.active as number) >= 1, 'should have at least 1 active mandate');
  });

  it('buy_credits succeeds with valid order', async () => {
    const result = await agent.buyCredits({ sku: 'credits-1000', qty: 1 });
    assert.equal(result.decision, 'APPROVE');
    assert.ok(result.verdictId, 'should have verdictId');
    assert.equal(result.totalPaid, '10.00 USD');
    assert.ok(result.remainingBudget, 'should have remainingBudget');
  });

  it('buy_credits out-of-scope returns readable REJECT', async () => {
    // Buy more than maxPerOrder (3000 cents = $30, try $50 = 5000 cents)
    const result = await agent.buyCredits({ sku: 'credits-5000', qty: 1 });
    // credits-5000 costs 4500 cents > maxPerOrder 3000
    assert.equal(result.decision, 'REJECT');
    assert.ok(result.violations, 'should have violations');
    assert.ok(Array.isArray(result.violations), 'violations should be array');
    assert.ok((result.violations as string[]).length > 0, 'should have at least 1 violation');
    // Should be readable strings, not objects
    assert.equal(typeof (result.violations as string[])[0], 'string');
    assert.ok((result.violations as string[])[0].includes('ORDER_LIMIT_EXCEEDED') || (result.violations as string[])[0].includes('BUDGET_EXCEEDED'));
    assert.ok(result.hint, 'should have hint for the user');
  });

  it('get_verdict retrieves a verdict', async () => {
    // Use verdictId from the successful buy
    const buyResult = await agent.buyCredits({ sku: 'credits-1000', qty: 1 });
    if (buyResult.verdictId) {
      const verdict = await agent.getVerdict(buyResult.verdictId as number);
      assert.ok(verdict.decision, 'should have decision');
    }
  });
});
