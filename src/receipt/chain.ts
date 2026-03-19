// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { GovernanceReceipt } from './model.js';
import { canonicalizeBytes } from '../crypto/canonicalize.js';
import { sha256Hex } from '../crypto/sha256.js';
import { verify } from '../crypto/ed25519.js';
import { hexToBytes } from '../crypto/sha256.js';

/**
 * Compute the hash of a receipt for chain linking.
 * SHA-256(canonicalize(receipt)) - INCLUDES the signature field.
 */
export async function computeReceiptHash(receipt: GovernanceReceipt): Promise<string> {
  const bytes = canonicalizeBytes(receipt);
  return sha256Hex(bytes);
}

/**
 * Verify an ordered chain of governance receipts.
 *
 * Checks:
 * 1. Algorithm field must be "Ed25519-SHA256-JCS" (fail closed on unknown)
 * 2. First receipt's previous_receipt_hash must be ""
 * 3. Each subsequent receipt's previous_receipt_hash must match
 *    computeReceiptHash(previousReceipt)
 * 4. Each receipt's Ed25519 signature must be valid
 */
export async function verifyChain(
  receipts: GovernanceReceipt[],
): Promise<{ valid: boolean; brokenAt?: number }> {
  for (let i = 0; i < receipts.length; i++) {
    const receipt = receipts[i];

    // Check algorithm
    if (receipt.algorithm !== 'Ed25519-SHA256-JCS') {
      return { valid: false, brokenAt: i };
    }

    // Check chain linkage
    if (i === 0) {
      if (receipt.previous_receipt_hash !== '') {
        return { valid: false, brokenAt: 0 };
      }
    } else {
      const expectedHash = await computeReceiptHash(receipts[i - 1]);
      if (receipt.previous_receipt_hash !== expectedHash) {
        return { valid: false, brokenAt: i };
      }
    }

    // Verify signature
    const toVerify = { ...receipt } as Record<string, unknown>;
    delete toVerify.signature;
    const canonicalBytes = canonicalizeBytes(toVerify);
    const sigBytes = hexToBytes(receipt.signature);
    const pubBytes = hexToBytes(receipt.public_key);

    const valid = await verify(pubBytes, canonicalBytes, sigBytes);
    if (!valid) {
      return { valid: false, brokenAt: i };
    }
  }

  return { valid: true };
}
