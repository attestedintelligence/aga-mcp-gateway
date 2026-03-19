// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP governance receipts
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { ToolPolicy } from '../governance/types.js';
import type { GovernanceReceipt } from '../receipt/types.js';
import { evaluate } from '../governance/policy.js';
import { generateReceipt, computeArgumentsHash } from '../receipt/generate.js';
import { sha256Hex } from '../crypto/sha256.js';
import { hexToBytes } from '../crypto/sha256.js';
import { canonicalize } from '../crypto/canonicalize.js';
import { MemoryReceiptChain } from '../storage/memory-chain.js';

const MAX_BODY_SIZE = 1024 * 1024; // 1 MB

export interface GatewayConfig {
  gatewayId: string;
  upstreamUrl: string;
  policy: ToolPolicy;
  policyHash: string;
  seed: Uint8Array;
  receiptChain: MemoryReceiptChain;
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
    return forwardToUpstream(config.upstreamUrl, requestBody);
  }

  // Step 6: tools/call with missing params.name: deny fail-closed
  const params = parsed.params as Record<string, unknown> | undefined;
  const toolName = params?.name as string | undefined;

  if (!toolName) {
    const decision = {
      allowed: false,
      reason: 'fail-closed: missing tool name',
      tool_name: 'UNKNOWN',
      policy_mode: config.policy.mode,
    };

    const head = await config.receiptChain.getHead();
    const receipt = await generateReceipt({
      gatewayId: config.gatewayId,
      toolName: 'UNKNOWN',
      argumentsHash: await computeArgumentsHash(null),
      decision,
      policyHash: config.policyHash,
      requestId: String(requestId ?? ''),
      previousReceiptHash: head.headHash,
      sequenceNumber: head.length,
      seed: config.seed,
    });
    await config.receiptChain.append(receipt);

    return jsonRpcError(requestId, -32600, 'Missing tool name', receipt);
  }

  // Step 7: Extract arguments
  const args = (params?.arguments as Record<string, unknown>) ?? null;

  // Step 8: Compute arguments_hash
  const argumentsHash = await computeArgumentsHash(args);

  // Step 9: Evaluate policy
  const decision = evaluate(config.policy, toolName, args ?? undefined);

  // Step 10: Generate signed receipt
  const head = await config.receiptChain.getHead();
  const receipt = await generateReceipt({
    gatewayId: config.gatewayId,
    toolName,
    argumentsHash,
    decision,
    policyHash: config.policyHash,
    requestId: String(requestId ?? ''),
    previousReceiptHash: head.headHash,
    sequenceNumber: head.length,
    seed: config.seed,
  });
  await config.receiptChain.append(receipt);

  // Step 11: PERMITTED -> forward; DENIED -> error
  if (decision.allowed) {
    const upstream = await forwardToUpstream(config.upstreamUrl, requestBody);
    return upstream;
  }

  return jsonRpcError(requestId, -32600, `Tool denied: ${decision.reason}`, receipt);
}

/**
 * Forward a request to the upstream MCP server.
 */
async function forwardToUpstream(upstreamUrl: string, body: string): Promise<Response> {
  const upstreamResp = await fetch(upstreamUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  });
  return new Response(upstreamResp.body, {
    status: upstreamResp.status,
    headers: upstreamResp.headers,
  });
}
