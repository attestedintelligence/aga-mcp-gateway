// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import { sha256Hex, hexToBytes } from '../crypto/sha256.js';

/**
 * Compute the SHA-256 hash of two concatenated 32-byte hash values.
 * Used as the internal node hash function in the binary Merkle tree.
 */
export async function merkleNodeHash(leftHex: string, rightHex: string): Promise<string> {
  const left = hexToBytes(leftHex);
  const right = hexToBytes(rightHex);
  const combined = new Uint8Array(left.length + right.length);
  combined.set(left, 0);
  combined.set(right, left.length);
  return sha256Hex(combined);
}

/**
 * Compute the Merkle root of a list of leaf hashes (hex strings).
 * Uses a binary Merkle tree construction:
 * - Pairs of nodes are hashed together at each level
 * - If there is an odd number of nodes, the last node is promoted
 *   directly to the next level (no duplication)
 */
export async function merkleRoot(leavesHex: string[]): Promise<string> {
  if (leavesHex.length === 0) {
    throw new Error('cannot compute Merkle root of empty list');
  }
  if (leavesHex.length === 1) {
    return leavesHex[0];
  }

  let currentLevel = [...leavesHex];

  while (currentLevel.length > 1) {
    const nextLevel: string[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      if (i + 1 < currentLevel.length) {
        // Pair exists: hash left + right
        const nodeHash = await merkleNodeHash(currentLevel[i], currentLevel[i + 1]);
        nextLevel.push(nodeHash);
      } else {
        // Odd node: promote directly
        nextLevel.push(currentLevel[i]);
      }
    }
    currentLevel = nextLevel;
  }

  return currentLevel[0];
}
