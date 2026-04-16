// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { Env } from './env.js';
import type { ToolPolicy } from './governance/types.js';
import { handleMCPRequest, type GatewayConfig } from './proxy/handler.js';
import { DurableObjectChainClient } from './storage/chain-client.js';
import { MemoryReceiptChain } from './storage/memory-chain.js';
import type { ReceiptChain } from './storage/chain-client.js';
import { sha256Hex, hexToBytes } from './crypto/sha256.js';
import { composeBundle } from './bundle/compose.js';
import { verifyBundle } from './bundle/verify.js';
import { getPublicKey } from './crypto/ed25519.js';
import { bytesToHex } from './crypto/sha256.js';

export { ReceiptChainDO } from './storage/durable-chain.js';

/**
 * Get the receipt chain client. Uses Durable Object if available,
 * falls back to in-memory for local dev without DO bindings.
 */
function getChainClient(env: Env): ReceiptChain {
  if (env.RECEIPT_CHAIN) {
    return new DurableObjectChainClient(env.RECEIPT_CHAIN, env.GATEWAY_ID);
  }
  // Fallback for local dev without DO binding
  return new MemoryReceiptChain();
}

/**
 * Build a GatewayConfig from Cloudflare Worker env bindings.
 */
async function buildConfig(env: Env): Promise<GatewayConfig> {
  const policy: ToolPolicy = JSON.parse(env.SEALED_POLICY);
  const policyHash = await sha256Hex(new TextEncoder().encode(env.SEALED_POLICY));
  const seed = hexToBytes(env.SIGNING_KEY_SEED);

  return {
    gatewayId: env.GATEWAY_ID,
    upstreamUrl: env.UPSTREAM_URL,
    policy,
    policyHash,
    seed,
    receiptChain: getChainClient(env),
    upstreamService: env.UPSTREAM_SERVICE,
  };
}

/**
 * Handle GET /receipts: return all receipts from the DO chain.
 */
async function handleGetReceipts(env: Env): Promise<Response> {
  const chain = getChainClient(env);
  const receipts = await chain.getReceipts();
  return new Response(JSON.stringify({ receipts, count: receipts.length }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Handle GET /bundle: compose and return an evidence bundle.
 */
async function handleGetBundle(env: Env): Promise<Response> {
  const chain = getChainClient(env);
  const receipts = await chain.getReceipts();
  if (receipts.length === 0) {
    return new Response(JSON.stringify({ error: 'no receipts to bundle' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const seed = hexToBytes(env.SIGNING_KEY_SEED);
  const pubKey = await getPublicKey(seed);
  const publicKeyHex = bytesToHex(pubKey);
  const policyHash = await sha256Hex(new TextEncoder().encode(env.SEALED_POLICY));

  const bundle = await composeBundle(receipts, env.GATEWAY_ID, publicKeyHex, policyHash);
  return new Response(JSON.stringify(bundle), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Handle POST /verify: verify a submitted evidence bundle.
 */
async function handleVerify(request: Request): Promise<Response> {
  try {
    const bundle = await request.json();
    const result = await verifyBundle(bundle);
    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: 'invalid bundle JSON' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

/**
 * Handle GET /health: basic health check with DO chain length.
 */
async function handleHealth(env: Env): Promise<Response> {
  const chain = getChainClient(env);
  const head = await chain.getHead();
  return new Response(JSON.stringify({
    status: 'ok',
    gateway_id: env.GATEWAY_ID,
    receipts: head.length,
  }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Security and CORS headers applied to every response. */
const securityHeaders: Record<string, string> = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function withHeaders(response: Response): Response {
  const patched = new Response(response.body, response);
  for (const [k, v] of Object.entries(securityHeaders)) {
    patched.headers.set(k, v);
  }
  return patched;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: securityHeaders });
    }

    const url = new URL(request.url);

    let response: Response;
    switch (url.pathname) {
      case '/mcp':
        response = await handleMCPRequest(request, await buildConfig(env));
        break;
      case '/receipts':
        response = await handleGetReceipts(env);
        break;
      case '/bundle':
        response = await handleGetBundle(env);
        break;
      case '/verify':
        response = await handleVerify(request);
        break;
      case '/health':
        response = await handleHealth(env);
        break;
      default:
        response = new Response('Not Found', { status: 404 });
    }

    return withHeaders(response);
  },
};
