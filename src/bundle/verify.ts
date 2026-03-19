// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP governance receipts
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { EvidenceBundle, VerificationResult } from './types.js';
import type { GovernanceReceipt } from '../receipt/types.js';
import { verify as ed25519Verify } from '../crypto/ed25519.js';
import { sha256Hex, hexToBytes } from '../crypto/sha256.js';
import { canonicalize } from '../crypto/canonicalize.js';
import { merkleNodeHash } from '../crypto/merkle.js';

const SUPPORTED_ALGORITHMS = ['Ed25519-SHA256-JCS'];

/**
 * Constant-time comparison of two hex strings.
 * Prevents timing attacks on hash/signature comparisons.
 */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Step 1: Validate the algorithm field.
 * Fail closed on unknown algorithms.
 */
function checkAlgorithm(bundle: EvidenceBundle): boolean {
  return SUPPORTED_ALGORITHMS.includes(bundle.algorithm);
}

/**
 * Step 2: Verify all receipt signatures.
 * Re-computes receipt_hash from the pre-hash fields and verifies
 * the Ed25519 signature against the public key in the bundle.
 */
async function checkReceiptSignatures(bundle: EvidenceBundle): Promise<boolean> {
  const publicKeyBytes = hexToBytes(bundle.public_key);

  for (const receipt of bundle.receipts) {
    // Reconstruct the pre-hash object (everything except receipt_hash and signature)
    const preHash: Record<string, unknown> = {
      schema_version: receipt.schema_version,
      receipt_id: receipt.receipt_id,
      gateway_id: receipt.gateway_id,
      timestamp: receipt.timestamp,
      sequence_number: receipt.sequence_number,
      tool_name: receipt.tool_name,
      arguments_hash: receipt.arguments_hash,
      decision: receipt.decision,
      reason: receipt.reason,
      policy_hash: receipt.policy_hash,
      request_id: receipt.request_id,
      previous_receipt_hash: receipt.previous_receipt_hash,
      public_key: receipt.public_key,
    };

    // Verify receipt_hash
    const canonical = canonicalize(preHash);
    const computedHash = await sha256Hex(new TextEncoder().encode(canonical));
    if (!constantTimeEqual(computedHash, receipt.receipt_hash)) {
      return false;
    }

    // Verify signature over receipt_hash
    const sigBytes = hexToBytes(receipt.signature);
    const msgBytes = new TextEncoder().encode(receipt.receipt_hash);
    const valid = await ed25519Verify(publicKeyBytes, msgBytes, sigBytes);
    if (!valid) {
      return false;
    }
  }

  return true;
}

/**
 * Step 3: Verify chain integrity.
 * Each receipt's previous_receipt_hash must match the preceding receipt's receipt_hash.
 * The first receipt should have an empty previous_receipt_hash.
 */
function checkChainIntegrity(bundle: EvidenceBundle): boolean {
  const receipts = bundle.receipts;
  if (receipts.length === 0) return true;

  // First receipt: previous_receipt_hash should be empty
  if (receipts[0].previous_receipt_hash !== '') {
    return false;
  }

  for (let i = 1; i < receipts.length; i++) {
    if (!constantTimeEqual(receipts[i].previous_receipt_hash, receipts[i - 1].receipt_hash)) {
      return false;
    }
  }

  return true;
}

/**
 * Step 4: Verify Merkle proofs.
 * For each proof, walk from the leaf to the root using the siblings,
 * then compare against the bundle's merkle_root.
 */
async function checkMerkleProofs(bundle: EvidenceBundle): Promise<boolean> {
  for (const proof of bundle.merkle_proofs) {
    let currentHash = proof.leaf_hash;

    for (let i = 0; i < proof.siblings.length; i++) {
      const sibling = proof.siblings[i];
      const direction = proof.directions[i];

      if (direction === 'left') {
        currentHash = await merkleNodeHash(sibling, currentHash);
      } else {
        currentHash = await merkleNodeHash(currentHash, sibling);
      }
    }

    if (!constantTimeEqual(currentHash, bundle.merkle_root)) {
      return false;
    }

    // Proof's own root should match bundle root
    if (!constantTimeEqual(proof.merkle_root, bundle.merkle_root)) {
      return false;
    }
  }

  return true;
}

/**
 * Step 5: Verify bundle consistency.
 * The number of proofs must match the number of receipts,
 * and each proof's leaf_hash must match the SHA-256 of the
 * corresponding receipt's receipt_hash.
 */
async function checkBundleConsistency(bundle: EvidenceBundle): Promise<boolean> {
  if (bundle.merkle_proofs.length !== bundle.receipts.length) {
    return false;
  }

  for (let i = 0; i < bundle.receipts.length; i++) {
    const expectedLeaf = await sha256Hex(
      new TextEncoder().encode(bundle.receipts[i].receipt_hash),
    );
    if (!constantTimeEqual(bundle.merkle_proofs[i].leaf_hash, expectedLeaf)) {
      return false;
    }
    if (bundle.merkle_proofs[i].leaf_index !== i) {
      return false;
    }
  }

  return true;
}

/**
 * Verify an evidence bundle per directive Section 14.
 * Five verification steps, all must pass for overall validity.
 */
export async function verifyBundle(bundle: EvidenceBundle): Promise<VerificationResult> {
  const result: VerificationResult = {
    algorithm_valid: false,
    receipt_signatures_valid: false,
    chain_integrity_valid: false,
    merkle_proofs_valid: false,
    bundle_consistent: false,
    overall_valid: false,
    receipts_checked: bundle.receipts.length,
    algorithm: bundle.algorithm,
  };

  // Step 1: Algorithm check (fail closed on unknown)
  result.algorithm_valid = checkAlgorithm(bundle);
  if (!result.algorithm_valid) {
    result.error = `unsupported algorithm: ${bundle.algorithm}`;
    return result;
  }

  // Step 2: Receipt signatures
  try {
    result.receipt_signatures_valid = await checkReceiptSignatures(bundle);
  } catch (e) {
    result.error = `signature verification error: ${e}`;
    return result;
  }

  // Step 3: Chain integrity
  result.chain_integrity_valid = checkChainIntegrity(bundle);

  // Step 4: Merkle proofs
  try {
    result.merkle_proofs_valid = await checkMerkleProofs(bundle);
  } catch (e) {
    result.error = `merkle proof error: ${e}`;
    return result;
  }

  // Step 5: Bundle consistency
  try {
    result.bundle_consistent = await checkBundleConsistency(bundle);
  } catch (e) {
    result.error = `consistency check error: ${e}`;
    return result;
  }

  result.overall_valid =
    result.algorithm_valid &&
    result.receipt_signatures_valid &&
    result.chain_integrity_valid &&
    result.merkle_proofs_valid &&
    result.bundle_consistent;

  return result;
}
