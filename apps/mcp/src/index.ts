#!/usr/bin/env node
/**
 * Mandate Clearing MCP Server
 *
 * Tools:
 *   request_mandate  — get a signed mandate from the principal
 *   list_mandates    — active mandates with remaining budget
 *   buy_credits      — purchase API credits under mandate
 *   get_verdict      — public verdict lookup
 *
 * Config: MANDATE_BASE_URL (default https://www.north7.ai/mandate)
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { MandateAgent } from './agent.js';

const BASE_URL = process.env.MANDATE_BASE_URL ?? 'https://www.north7.ai/mandate';
const agent = new MandateAgent(BASE_URL);

const server = new Server(
  { name: 'mandate-clearing-mcp', version: '0.1.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'request_mandate',
      description: 'Request a signed mandate from the principal. Returns an approval URL — the user must open it and approve. Then returns the signed mandate with budget info.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          categories: { type: 'array', items: { type: 'string' }, description: 'Allowed spending categories (e.g. ["api-credits"])' },
          merchants: { type: 'array', items: { type: 'string' }, description: 'Allowed merchants (e.g. ["north7.ai"])' },
          maxPerOrder: { type: 'number', description: 'Max amount per order in cents (e.g. 5000 = $50)' },
          maxTotal: { type: 'number', description: 'Total budget in cents (e.g. 10000 = $100)' },
          hours: { type: 'number', description: 'Mandate validity in hours (e.g. 24)' },
        },
        required: ['categories', 'merchants', 'maxTotal', 'hours'],
      },
    },
    {
      name: 'list_mandates',
      description: 'List active mandates with remaining budget.',
      inputSchema: { type: 'object' as const, properties: {} },
    },
    {
      name: 'buy_credits',
      description: 'Buy API credits from north7.ai under an active mandate. Returns the verdict (APPROVE with receipt, or REJECT with violations explained).',
      inputSchema: {
        type: 'object' as const,
        properties: {
          sku: { type: 'string', description: 'Product SKU (e.g. "credits-1000" or "credits-5000")' },
          qty: { type: 'number', description: 'Quantity to buy' },
          mandateId: { type: 'string', description: 'Mandate ID to use (optional — uses most recent if omitted)' },
        },
        required: ['sku', 'qty'],
      },
    },
    {
      name: 'get_verdict',
      description: 'Look up a verdict by ID from the public verdict explorer.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          id: { type: 'number', description: 'Verdict ID' },
        },
        required: ['id'],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'request_mandate': {
        const result = await agent.requestMandate({
          categories: (args as any).categories ?? ['api-credits'],
          merchants: (args as any).merchants ?? ['north7.ai'],
          maxPerOrder: (args as any).maxPerOrder,
          maxTotal: (args as any).maxTotal,
          hours: (args as any).hours ?? 24,
        });
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      }

      case 'list_mandates': {
        const result = await agent.listMandates();
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      }

      case 'buy_credits': {
        const result = await agent.buyCredits({
          sku: (args as any).sku,
          qty: (args as any).qty,
          mandateId: (args as any).mandateId,
        });
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      }

      case 'get_verdict': {
        const result = await agent.getVerdict((args as any).id);
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      }

      default:
        return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
    }
  } catch (err) {
    return {
      content: [{ type: 'text', text: `Error: ${(err as Error).message}` }],
      isError: true,
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
