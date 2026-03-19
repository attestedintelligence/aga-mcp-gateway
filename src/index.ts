// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP governance receipts
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { Env } from './env.js';
import type { ToolPolicy } from './governance/types.js';
import { handleMCPRequest, type GatewayConfig } from './proxy/handler.js';
import { MemoryReceiptChain } from './storage/memory-chain.js';
import { sha256Hex, hexToBytes } from './crypto/sha256.js';
import { composeBundle } from './bundle/compose.js';
import { verifyBundle } from './bundle/verify.js';
import { getPublicKey } from './crypto/ed25519.js';
import { bytesToHex } from './crypto/sha256.js';

// Shared in-memory receipt chain (per-isolate, not persistent)
const receiptChain = new MemoryReceiptChain();

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
    receiptChain,
  };
}

/**
 * Handle GET /receipts: return all receipts from the in-memory chain.
 */
async function handleGetReceipts(): Promise<Response> {
  const receipts = await receiptChain.getReceipts();
  return new Response(JSON.stringify({ receipts, count: receipts.length }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Handle GET /bundle: compose and return an evidence bundle.
 */
async function handleGetBundle(env: Env): Promise<Response> {
  const receipts = await receiptChain.getReceipts();
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
 * Handle GET /health: basic health check.
 */
async function handleHealth(env: Env): Promise<Response> {
  const head = await receiptChain.getHead();
  return new Response(JSON.stringify({
    status: 'ok',
    gateway_id: env.GATEWAY_ID,
    receipts: head.length,
  }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    switch (url.pathname) {
      case '/mcp':
        return handleMCPRequest(request, await buildConfig(env));
      case '/receipts':
        return handleGetReceipts();
      case '/bundle':
        return handleGetBundle(env);
      case '/verify':
        return handleVerify(request);
      case '/health':
        return handleHealth(env);
      default:
        return new Response('Not Found', { status: 404 });
    }
  },
};
