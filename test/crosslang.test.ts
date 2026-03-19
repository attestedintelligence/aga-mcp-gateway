// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import { sha256Fields, sha256Hex, hexToBytes } from '../src/crypto/sha256.js';
import { normalizeTimestamp } from '../src/crypto/timestamp.js';
import { merkleRoot, merkleNodeHash } from '../src/bundle/merkle.js';
import vectors from './vectors/aga_test_vectors.json';

/**
 * Compute a leaf hash using the AGA length-prefixed field hashing scheme.
 * This matches the Go reference implementation exactly.
 */
async function computeLeafHash(
  schemaVersion: string,
  protocolVersion: string,
  eventType: string,
  eventID: string,
  sequenceNumber: number,
  timestamp: string,
  previousLeafHashHex: string,
): Promise<string> {
  const encoder = new TextEncoder();
  return sha256Fields(
    encoder.encode(schemaVersion),
    encoder.encode(protocolVersion),
    encoder.encode(eventType),
    encoder.encode(eventID),
    encoder.encode(sequenceNumber.toString()),
    encoder.encode(normalizeTimestamp(timestamp)),
    hexToBytes(previousLeafHashHex),
  );
}

describe('Cross-language: leaf hash vectors', () => {
  for (const vec of vectors.leaf_hash_vectors) {
    it(`should match leaf hash vector: ${vec.id}`, async () => {
      const { inputs, expected_leaf_hash_hex } = vec;
      const hash = await computeLeafHash(
        inputs.schema_version,
        inputs.protocol_version,
        inputs.event_type,
        inputs.event_id,
        inputs.sequence_number,
        inputs.timestamp,
        inputs.previous_leaf_hash_hex,
      );
      expect(hash).toBe(expected_leaf_hash_hex);
    });
  }
});

describe('Cross-language: seal vectors', () => {
  for (const vec of vectors.seal_vectors) {
    it(`should match seal vector: ${vec.id}`, async () => {
      const { inputs, expected_sealed_hash_hex } = vec;
      const hash = await sha256Fields(
        hexToBytes(inputs.bytes_hash_hex),
        hexToBytes(inputs.metadata_hash_hex),
        hexToBytes(inputs.policy_reference_hex),
        hexToBytes(inputs.salt_hex),
      );
      expect(hash).toBe(expected_sealed_hash_hex);
    });
  }
});

describe('Cross-language: Merkle tree vectors', () => {
  it('should match merkle-4-leaves root and intermediate nodes', async () => {
    const vec = vectors.merkle_vectors[0];
    const leaves = vec.inputs.leaves_hex;

    // Verify intermediate nodes
    const node01 = await merkleNodeHash(leaves[0], leaves[1]);
    expect(node01).toBe(vec.expected.node_0_1_hex);

    const node23 = await merkleNodeHash(leaves[2], leaves[3]);
    expect(node23).toBe(vec.expected.node_2_3_hex);

    // Verify root
    const root = await merkleRoot(leaves);
    expect(root).toBe(vec.expected.merkle_root_hex);

    // Verify inclusion proof for leaf 0
    const proof = vec.inclusion_proof_for_leaf_0;
    let current = leaves[0];
    for (let i = 0; i < proof.sibling_hashes_hex.length; i++) {
      const sibling = proof.sibling_hashes_hex[i];
      if (proof.directions[i] === 'right') {
        current = await merkleNodeHash(current, sibling);
      } else {
        current = await merkleNodeHash(sibling, current);
      }
    }
    expect(current).toBe(vec.expected.merkle_root_hex);
  });

  it('should match merkle-3-leaves-odd root', async () => {
    const vec = vectors.merkle_vectors[1];
    const leaves = vec.inputs.leaves_hex;

    // Verify intermediate node
    const node01 = await merkleNodeHash(leaves[0], leaves[1]);
    expect(node01).toBe(vec.expected.node_0_1_hex);

    // Verify root
    const root = await merkleRoot(leaves);
    expect(root).toBe(vec.expected.merkle_root_hex);
  });
});

describe('Cross-language: timestamp normalization', () => {
  for (const vec of vectors.timestamp_normalization_vectors) {
    it(`should normalize: ${vec.id}`, () => {
      const result = normalizeTimestamp(vec.input);
      expect(result).toBe(vec.expected_normalized);
    });
  }
});
