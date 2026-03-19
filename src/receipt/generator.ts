// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP governance receipts
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { GovernanceReceipt } from './model.js';
import { canonicalize, canonicalizeBytes } from '../crypto/canonicalize.js';
import { sha256Hex } from '../crypto/sha256.js';
import { sign, getPublicKey } from '../crypto/ed25519.js';
import { bytesToHex } from '../crypto/sha256.js';

/**
 * Generate a governance receipt with Ed25519 signature.
 *
 * Arguments hash tri-state per Section 3.5:
 * - arguments undefined (absent): hash = ""
 * - arguments is empty object: hash = SHA-256("{}")
 * - arguments has content: hash = SHA-256(canonicalize(arguments))
 */
export async function generateReceipt(params: {
  toolName: string;
  decision: 'PERMITTED' | 'DENIED';
  reason: string;
  requestId: string | number | null;
  arguments?: Record<string, unknown>;
  policyReference: string;
  previousReceiptHash: string;
  gatewayId: string;
  signingKeySeed: Uint8Array;
}): Promise<GovernanceReceipt> {
  // Compute arguments_hash per tri-state rules
  let argumentsHash: string;
  if (params.arguments === undefined) {
    argumentsHash = '';
  } else {
    const canonical = canonicalize(params.arguments);
    const bytes = new TextEncoder().encode(canonical);
    argumentsHash = await sha256Hex(bytes);
  }

  // Derive public key
  const pubKey = await getPublicKey(params.signingKeySeed);
  const publicKeyHex = bytesToHex(pubKey);

  // Construct receipt without signature
  const receipt: GovernanceReceipt = {
    receipt_id: crypto.randomUUID(),
    receipt_version: '1.0',
    algorithm: 'Ed25519-SHA256-JCS',
    timestamp: new Date().toISOString(),
    request_id: params.requestId,
    method: 'tools/call',
    tool_name: params.toolName,
    decision: params.decision,
    reason: params.reason,
    policy_reference: params.policyReference,
    arguments_hash: argumentsHash,
    previous_receipt_hash: params.previousReceiptHash,
    gateway_id: params.gatewayId,
    signature: '',
    public_key: publicKeyHex,
  };

  // Canonicalize receipt WITHOUT signature field
  const toSign = { ...receipt } as Record<string, unknown>;
  delete toSign.signature;
  const canonicalBytes = canonicalizeBytes(toSign);

  // Sign
  const sig = await sign(params.signingKeySeed, canonicalBytes);
  receipt.signature = bytesToHex(sig);

  return receipt;
}
