// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { ToolPolicy } from '../governance/types.js';
import type { GovernanceReceipt } from '../receipt/model.js';
import type { ReceiptChain } from '../storage/chain-client.js';
import { evaluate } from '../governance/policy.js';
import { generateReceipt } from '../receipt/generator.js';

const MAX_BODY_SIZE = 1024 * 1024; // 1 MB

export interface GatewayConfig {
  gatewayId: string;
  upstreamUrl: string;
  policy: ToolPolicy;
  policyHash: string;
  seed: Uint8Array;
  receiptChain: ReceiptChain;
  upstreamService?: Fetcher;
}

/**
 * Build a JSON-RPC error response at HTTP 200.
 */
function jsonRpcError(
  id: string | number | null,
  code: number,
  message: string,
  receipt?: GovernanceReceipt,
): Response {
  const body: Record<string, unknown> = {
    jsonrpc: '2.0',
    error: { code, message },
    id,
  };
  if (receipt) {
    body['x-aga-receipt'] = receipt;
  }
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Handle an incoming MCP request.
 * Implements the full proxy flow per the AGA Gateway Directive.
 */
export async function handleMCPRequest(
  request: Request,
  config: GatewayConfig,
): Promise<Response> {
  // Step 1: Content-Length check
  const contentLength = request.headers.get('content-length');
  if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) {
    return new Response('Request body too large', { status: 413 });
  }

  // Step 2: Read body
  const requestBody = await request.text();
  if (new TextEncoder().encode(requestBody).length > MAX_BODY_SIZE) {
    return new Response('Request body too large', { status: 413 });
  }

  // Step 3: Parse JSON
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(requestBody);
  } catch {
    return jsonRpcError(null, -32700, 'Parse error');
  }

  // Step 4: Validate jsonrpc version
  if (parsed.jsonrpc !== '2.0') {
    return new Response(
      JSON.stringify({ error: 'Missing or invalid jsonrpc version' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    );
  }

  const requestId = (parsed.id as string | number | null) ?? null;
  const method = parsed.method as string | undefined;

  // Step 5: Non-tools/call methods: forward transparently
  if (method !== 'tools/call') {
    return forwardToUpstream(config.upstreamUrl, requestBody, config.upstreamService);
  }

  // Step 6: tools/call with missing params.name: deny fail-closed
  const params = parsed.params as Record<string, unknown> | undefined;
  const toolName = params?.name as string | undefined;

  if (!toolName) {
    let head = await config.receiptChain.getHead();
    let receipt = await generateReceipt({
      toolName: 'UNKNOWN',
      decision: 'DENIED',
      reason: 'tool name extraction failed, fail-closed',
      requestId,
      policyReference: config.policyHash,
      previousReceiptHash: head.headHash,
      gatewayId: config.gatewayId,
      signingKeySeed: config.seed,
    });

    // Append to chain with single retry on conflict
    let appendResult = await config.receiptChain.append(receipt);
    if (appendResult.conflict) {
      head = await config.receiptChain.getHead();
      receipt = await generateReceipt({
        toolName: 'UNKNOWN',
        decision: 'DENIED',
        reason: 'tool name extraction failed, fail-closed',
        requestId,
        policyReference: config.policyHash,
        previousReceiptHash: head.headHash,
        gatewayId: config.gatewayId,
        signingKeySeed: config.seed,
      });
      appendResult = await config.receiptChain.append(receipt);
      if (appendResult.conflict) {
        return new Response('Service Unavailable: chain contention', { status: 503 });
      }
    }

    return jsonRpcError(requestId, -32600, 'Missing tool name', receipt);
  }

  // Step 7: Extract arguments
  const args = params?.arguments as Record<string, unknown> | undefined;

  // Step 9: Evaluate policy
  const decision = evaluate(config.policy, toolName, args);

  // Step 10: Generate signed receipt
  let head = await config.receiptChain.getHead();
  let receipt = await generateReceipt({
    toolName,
    decision: decision.allowed ? 'PERMITTED' : 'DENIED',
    reason: decision.reason,
    requestId,
    arguments: args,
    policyReference: config.policyHash,
    previousReceiptHash: head.headHash,
    gatewayId: config.gatewayId,
    signingKeySeed: config.seed,
  });

  // Append to chain with single retry on conflict
  let appendResult = await config.receiptChain.append(receipt);
  if (appendResult.conflict) {
    head = await config.receiptChain.getHead();
    receipt = await generateReceipt({
      toolName,
      decision: decision.allowed ? 'PERMITTED' : 'DENIED',
      reason: decision.reason,
      requestId,
      arguments: args,
      policyReference: config.policyHash,
      previousReceiptHash: head.headHash,
      gatewayId: config.gatewayId,
      signingKeySeed: config.seed,
    });
    appendResult = await config.receiptChain.append(receipt);
    if (appendResult.conflict) {
      return new Response('Service Unavailable: chain contention', { status: 503 });
    }
  }

  // Step 11: PERMITTED -> forward; DENIED -> error
  if (decision.allowed) {
    const upstream = await forwardToUpstream(config.upstreamUrl, requestBody, config.upstreamService);
    return upstream;
  }

  return jsonRpcError(requestId, -32600, `Tool denied: ${decision.reason}`, receipt);
}

/**
 * Forward a request to the upstream MCP server.
 * Uses service binding if available (avoids Cloudflare error 1042),
 * falls back to fetch with UPSTREAM_URL.
 */
async function forwardToUpstream(
  upstreamUrl: string,
  body: string,
  upstreamService?: Fetcher,
): Promise<Response> {
  const init: RequestInit = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  };

  let upstreamResp: Response;
  if (upstreamService) {
    upstreamResp = await upstreamService.fetch(new Request(upstreamUrl, init));
  } else {
    upstreamResp = await fetch(upstreamUrl, init);
  }

  return new Response(upstreamResp.body, {
    status: upstreamResp.status,
    headers: upstreamResp.headers,
  });
}
