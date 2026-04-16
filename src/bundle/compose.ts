// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { GovernanceReceipt } from '../receipt/model.js';
import type { EvidenceBundle, MerkleProof } from './types.js';
import { merkleRoot, merkleNodeHash } from '../bundle/merkle.js';
import { sha256Hex } from '../crypto/sha256.js';
import { canonicalizeBytes } from '../crypto/canonicalize.js';

const ALGORITHM = 'Ed25519-SHA256-JCS';

/**
 * Compute the leaf hash for a receipt:
 * SHA-256(canonicalize(receipt)) where receipt includes the signature field.
 */
async function receiptLeafHash(receipt: GovernanceReceipt): Promise<string> {
  return sha256Hex(canonicalizeBytes(receipt));
}

/**
 * Generate a Merkle inclusion proof for a specific leaf index.
 * Walks the binary Merkle tree level by level, collecting sibling hashes.
 */
async function generateMerkleProof(
  leaves: string[],
  leafIndex: number,
): Promise<MerkleProof> {
  const siblings: string[] = [];
  const directions: ('left' | 'right')[] = [];

  let currentLevel = [...leaves];
  let idx = leafIndex;

  while (currentLevel.length > 1) {
    const nextLevel: string[] = [];

    for (let i = 0; i < currentLevel.length; i += 2) {
      if (i + 1 < currentLevel.length) {
        const nodeHash = await merkleNodeHash(currentLevel[i], currentLevel[i + 1]);
        nextLevel.push(nodeHash);
      } else {
        // Odd node promoted directly
        nextLevel.push(currentLevel[i]);
      }
    }

    // Determine sibling for current index
    if (idx % 2 === 0) {
      // Current is left child
      if (idx + 1 < currentLevel.length) {
        siblings.push(currentLevel[idx + 1]);
        directions.push('right');
      }
      // If no sibling (odd node), no entry needed for this level
    } else {
      // Current is right child
      siblings.push(currentLevel[idx - 1]);
      directions.push('left');
    }

    idx = Math.floor(idx / 2);
    currentLevel = nextLevel;
  }

  const root = currentLevel[0];
  return {
    leaf_hash: leaves[leafIndex],
    leaf_index: leafIndex,
    siblings,
    directions,
    merkle_root: root,
  };
}

/**
 * Compose an evidence bundle from a list of governance receipts.
 * Computes the Merkle root and generates inclusion proofs for each receipt.
 */
export async function composeBundle(
  receipts: GovernanceReceipt[],
  gatewayId: string,
  publicKeyHex: string,
  policyReference: string,
): Promise<EvidenceBundle> {
  if (receipts.length === 0) {
    throw new Error('cannot compose bundle with zero receipts');
  }

  // Compute leaf hashes
  const leafHashes = await Promise.all(receipts.map(r => receiptLeafHash(r)));

  // Compute Merkle root
  const root = await merkleRoot(leafHashes);

  // Generate inclusion proofs for each receipt
  const proofs = await Promise.all(
    leafHashes.map((_, i) => generateMerkleProof(leafHashes, i)),
  );

  return {
    schema_version: '1.0',
    bundle_id: crypto.randomUUID(),
    algorithm: ALGORITHM,
    generated_at: new Date().toISOString(),
    gateway_id: gatewayId,
    public_key: publicKeyHex,
    policy_reference: policyReference,
    receipts,
    merkle_root: root,
    merkle_proofs: proofs,
    offline_capable: true,
  };
}
