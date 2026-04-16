// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { EvidenceBundle, VerificationResult } from './types.js';
import type { GovernanceReceipt } from '../receipt/model.js';
import { verify as ed25519Verify } from '../crypto/ed25519.js';
import { sha256Hex, hexToBytes } from '../crypto/sha256.js';
import { canonicalizeBytes } from '../crypto/canonicalize.js';
import { merkleNodeHash } from '../bundle/merkle.js';

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
  if (!SUPPORTED_ALGORITHMS.includes(bundle.algorithm)) {
    return false;
  }
  // Also check every receipt's algorithm
  for (const receipt of bundle.receipts) {
    if (receipt.algorithm !== 'Ed25519-SHA256-JCS') {
      return false;
    }
  }
  return true;
}

/**
 * Step 2: Verify all receipt signatures.
 * For each receipt: remove signature, canonicalize, Ed25519 verify.
 */
async function checkReceiptSignatures(bundle: EvidenceBundle): Promise<boolean> {
  for (const receipt of bundle.receipts) {
    const { signature, ...receiptWithoutSig } = receipt;
    const canonical = canonicalizeBytes(receiptWithoutSig);
    const sigBytes = hexToBytes(signature);
    const pubBytes = hexToBytes(receipt.public_key);
    const valid = await ed25519Verify(pubBytes, canonical, sigBytes);
    if (!valid) {
      return false;
    }
  }
  return true;
}

/**
 * Step 3: Verify chain integrity.
 * Chain hash = SHA-256(canonicalize(receipt WITH signature)).
 * receipt[0].previous_receipt_hash === ""
 * receipt[i].previous_receipt_hash === chainHash(receipt[i-1])
 */
async function checkChainIntegrity(bundle: EvidenceBundle): Promise<boolean> {
  const receipts = bundle.receipts;
  if (receipts.length === 0) return true;

  if (receipts[0].previous_receipt_hash !== '') {
    return false;
  }

  for (let i = 1; i < receipts.length; i++) {
    // Chain hash includes signature
    const prevCanonical = canonicalizeBytes(receipts[i - 1]);
    const expectedHash = await sha256Hex(prevCanonical);
    if (!constantTimeEqual(receipts[i].previous_receipt_hash, expectedHash)) {
      return false;
    }
  }

  return true;
}

/**
 * Step 4: Verify Merkle proofs.
 * Walk each proof from leaf to root. Constant-time compare to bundle root.
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

    if (!constantTimeEqual(proof.merkle_root, bundle.merkle_root)) {
      return false;
    }
  }

  return true;
}

/**
 * Step 5: Verify bundle consistency.
 * Leaf hash = SHA-256(canonicalize(receipt WITH signature)).
 * Proof count must match receipt count.
 */
async function checkBundleConsistency(bundle: EvidenceBundle): Promise<boolean> {
  if (bundle.merkle_proofs.length !== bundle.receipts.length) {
    return false;
  }

  for (let i = 0; i < bundle.receipts.length; i++) {
    const leafHash = await sha256Hex(canonicalizeBytes(bundle.receipts[i]));
    if (!constantTimeEqual(bundle.merkle_proofs[i].leaf_hash, leafHash)) {
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
  try {
    result.chain_integrity_valid = await checkChainIntegrity(bundle);
  } catch (e) {
    result.error = `chain integrity error: ${e}`;
    return result;
  }

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
