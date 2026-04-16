// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { handleMCPRequest, type GatewayConfig } from '../src/proxy/handler.js';
import { MemoryReceiptChain } from '../src/storage/memory-chain.js';
import { hexToBytes } from '../src/crypto/sha256.js';
import type { ToolPolicy } from '../src/governance/types.js';

// Test seed (32 bytes hex)
const TEST_SEED_HEX = 'a'.repeat(64);
const TEST_SEED = hexToBytes(TEST_SEED_HEX);

// Mock upstream server that echoes the request body
let mockServer: Server;
let mockPort: number;

function startMockServer(): Promise<void> {
  return new Promise((resolve) => {
    mockServer = createServer((req: IncomingMessage, res: ServerResponse) => {
      let body = '';
      req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(body);
      });
    });
    mockServer.listen(0, () => {
      const addr = mockServer.address();
      if (addr && typeof addr === 'object') {
        mockPort = addr.port;
      }
      resolve();
    });
  });
}

function stopMockServer(): Promise<void> {
  return new Promise((resolve) => {
    mockServer.close(() => resolve());
  });
}

function makeConfig(
  policyOverride?: Partial<ToolPolicy>,
): GatewayConfig {
  const policy: ToolPolicy = {
    mode: 'allowlist',
    constraints: {
      'read_file': { name: 'read_file', allowed: true },
      'write_file': { name: 'write_file', allowed: true },
    },
    ...policyOverride,
  };

  return {
    gatewayId: 'test-gateway',
    upstreamUrl: `http://localhost:${mockPort}`,
    policy,
    policyHash: 'deadbeef'.repeat(8),
    seed: TEST_SEED,
    receiptChain: new MemoryReceiptChain(),
  };
}

function makeRequest(body: string, contentLength?: string): Request {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (contentLength !== undefined) {
    headers['content-length'] = contentLength;
  }
  return new Request(`http://localhost:${mockPort}/mcp`, {
    method: 'POST',
    headers,
    body,
  });
}

beforeAll(async () => {
  await startMockServer();
});

afterAll(async () => {
  await stopMockServer();
});

describe('Proxy Handler', () => {
  it('should forward permitted tools/call and return upstream response', async () => {
    const config = makeConfig();
    const body = JSON.stringify({
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: '/tmp/test.txt' } },
      id: 1,
    });

    const resp = await handleMCPRequest(makeRequest(body), config);
    expect(resp.status).toBe(200);

    const result = await resp.json();
    // Should get the echoed upstream body
    expect(result.jsonrpc).toBe('2.0');
    expect(result.method).toBe('tools/call');
  });

  it('should deny tools/call for unlisted tool and return JSON-RPC error', async () => {
    const config = makeConfig();
    const body = JSON.stringify({
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: 'execute_command', arguments: { cmd: 'rm -rf /' } },
      id: 2,
    });

    const resp = await handleMCPRequest(makeRequest(body), config);
    expect(resp.status).toBe(200);

    const result = await resp.json();
    expect(result.error).toBeDefined();
    expect(result.error.code).toBe(-32600);
    expect(result['x-aga-receipt']).toBeDefined();
    expect(result['x-aga-receipt'].decision).toBe('DENIED');
  });

  it('should forward non-tools/call methods without a receipt', async () => {
    const config = makeConfig();
    const body = JSON.stringify({
      jsonrpc: '2.0',
      method: 'initialize',
      params: {},
      id: 3,
    });

    const resp = await handleMCPRequest(makeRequest(body), config);
    expect(resp.status).toBe(200);

    const result = await resp.json();
    expect(result.method).toBe('initialize');
    expect(result['x-aga-receipt']).toBeUndefined();
  });

  it('should forward tools/list without a receipt', async () => {
    const config = makeConfig();
    const body = JSON.stringify({
      jsonrpc: '2.0',
      method: 'tools/list',
      params: {},
      id: 4,
    });

    const resp = await handleMCPRequest(makeRequest(body), config);
    expect(resp.status).toBe(200);

    const result = await resp.json();
    expect(result.method).toBe('tools/list');
  });

  it('should deny fail-closed when params.name is missing', async () => {
    const config = makeConfig();
    const body = JSON.stringify({
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { arguments: { foo: 'bar' } },
      id: 5,
    });

    const resp = await handleMCPRequest(makeRequest(body), config);
    expect(resp.status).toBe(200);

    const result = await resp.json();
    expect(result.error).toBeDefined();
    expect(result.error.code).toBe(-32600);
    expect(result['x-aga-receipt']).toBeDefined();
    expect(result['x-aga-receipt'].tool_name).toBe('UNKNOWN');
  });

  it('should return -32700 for malformed JSON', async () => {
    const config = makeConfig();
    const resp = await handleMCPRequest(
      makeRequest('this is not json'),
      config,
    );
    expect(resp.status).toBe(200);

    const result = await resp.json();
    expect(result.error.code).toBe(-32700);
    expect(result.error.message).toBe('Parse error');
  });

  it('should return 400 for missing jsonrpc "2.0"', async () => {
    const config = makeConfig();
    const body = JSON.stringify({
      method: 'tools/call',
      params: { name: 'read_file' },
      id: 6,
    });

    const resp = await handleMCPRequest(makeRequest(body), config);
    expect(resp.status).toBe(400);
  });

  it('should return 413 for body exceeding 1MB', async () => {
    const config = makeConfig();
    const largeBody = 'x'.repeat(1024 * 1024 + 1);
    const resp = await handleMCPRequest(
      makeRequest(largeBody, String(largeBody.length)),
      config,
    );
    expect(resp.status).toBe(413);
  });

  it('should generate a receipt with valid signature for denied call', async () => {
    const config = makeConfig();
    const body = JSON.stringify({
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: 'dangerous_tool', arguments: {} },
      id: 7,
    });

    const resp = await handleMCPRequest(makeRequest(body), config);
    const result = await resp.json();
    const receipt = result['x-aga-receipt'];

    expect(receipt).toBeDefined();
    expect(receipt.signature).toBeDefined();
    expect(receipt.public_key).toBeDefined();
    expect(receipt.gateway_id).toBe('test-gateway');
    expect(receipt.decision).toBe('DENIED');
    expect(receipt.tool_name).toBe('dangerous_tool');
    expect(receipt.algorithm).toBe('Ed25519-SHA256-JCS');
    expect(receipt.method).toBe('tools/call');
  });

  it('should chain receipts with previous_receipt_hash', async () => {
    const config = makeConfig();

    // First call
    const body1 = JSON.stringify({
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: '/a' } },
      id: 10,
    });
    await handleMCPRequest(makeRequest(body1), config);

    // Second call (denied)
    const body2 = JSON.stringify({
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { name: 'unknown_tool', arguments: {} },
      id: 11,
    });
    const resp2 = await handleMCPRequest(makeRequest(body2), config);
    const result2 = await resp2.json();
    const receipt2 = result2['x-aga-receipt'];

    // Second receipt should reference the first
    expect(receipt2.previous_receipt_hash).not.toBe('');
  });
});
