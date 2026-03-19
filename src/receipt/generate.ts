// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP governance receipts
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { GovernanceReceipt } from './types.js';
import type { ToolCallDecision } from '../governance/types.js';
import { canonicalize } from '../crypto/canonicalize.js';
import { sha256Hex, bytesToHex } from '../crypto/sha256.js';
import { sign, getPublicKey } from '../crypto/ed25519.js';

/**
 * Compute the arguments_hash per tri-state rules:
 * - null/undefined arguments: hash of empty string
 * - empty object {}: hash of "{}"
 * - non-empty: hash of JCS-canonicalized JSON
 */
export async function computeArgumentsHash(
  args: Record<string, unknown> | null | undefined,
): Promise<string> {
  if (args === null || args === undefined) {
    return sha256Hex(new TextEncoder().encode(''));
  }
  const canonical = canonicalize(args);
  return sha256Hex(new TextEncoder().encode(canonical));
}

/**
 * Generate a signed governance receipt for a tool call decision.
 */
export async function generateReceipt(params: {
  gatewayId: string;
  toolName: string;
  argumentsHash: string;
  decision: ToolCallDecision;
  policyHash: string;
  requestId: string;
  previousReceiptHash: string;
  sequenceNumber: number;
  seed: Uint8Array;
}): Promise<GovernanceReceipt> {
  const {
    gatewayId, toolName, argumentsHash, decision,
    policyHash, requestId, previousReceiptHash,
    sequenceNumber, seed,
  } = params;

  const timestamp = new Date().toISOString().replace(/\.000Z$/, 'Z');
  const receiptId = `rcpt-${Date.now()}-${sequenceNumber}`;

  const pubKey = await getPublicKey(seed);
  const publicKeyHex = bytesToHex(pubKey);

  // Build receipt without hash and signature first
  const preHash: Omit<GovernanceReceipt, 'receipt_hash' | 'signature'> = {
    schema_version: '1.0',
    receipt_id: receiptId,
    gateway_id: gatewayId,
    timestamp,
    sequence_number: sequenceNumber,
    tool_name: toolName,
    arguments_hash: argumentsHash,
    decision: decision.allowed ? 'PERMITTED' : 'DENIED',
    reason: decision.reason,
    policy_hash: policyHash,
    request_id: requestId,
    previous_receipt_hash: previousReceiptHash,
    public_key: publicKeyHex,
  };

  // Compute receipt hash over canonical form
  const canonical = canonicalize(preHash);
  const receiptHash = await sha256Hex(new TextEncoder().encode(canonical));

  // Sign the receipt hash
  const encoder = new TextEncoder();
  const sig = await sign(seed, encoder.encode(receiptHash));
  const signatureHex = bytesToHex(sig);

  return {
    ...preHash,
    receipt_hash: receiptHash,
    signature: signatureHex,
  };
}
