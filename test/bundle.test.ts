// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import { composeBundle } from '../src/bundle/compose.js';
import { verifyBundle } from '../src/bundle/verify.js';
import type { GovernanceReceipt } from '../src/receipt/model.js';
import { generateReceipt } from '../src/receipt/generator.js';
import { computeReceiptHash } from '../src/receipt/chain.js';
import { hexToBytes, bytesToHex } from '../src/crypto/sha256.js';
import { getPublicKey } from '../src/crypto/ed25519.js';

const TEST_SEED_HEX = 'b'.repeat(64);
const TEST_SEED = hexToBytes(TEST_SEED_HEX);

/**
 * Generate a chain of N receipts for testing.
 */
async function generateReceiptChain(count: number): Promise<GovernanceReceipt[]> {
  const receipts: GovernanceReceipt[] = [];
  let previousHash = '';

  for (let i = 0; i < count; i++) {
    const receipt = await generateReceipt({
      toolName: `tool_${i}`,
      decision: i % 2 === 0 ? 'PERMITTED' : 'DENIED',
      reason: i % 2 === 0 ? 'permitted by policy' : 'denied by policy',
      requestId: `req-${i}`,
      arguments: { index: i },
      policyReference: 'cafe'.repeat(16),
      previousReceiptHash: previousHash,
      gatewayId: 'test-gateway',
      signingKeySeed: TEST_SEED,
    });

    previousHash = await computeReceiptHash(receipt);
    receipts.push(receipt);
  }

  return receipts;
}

describe('Bundle Compose and Verify', () => {
  it('should compose a 10-receipt bundle and verify it', async () => {
    const receipts = await generateReceiptChain(10);
    const pubKey = await getPublicKey(TEST_SEED);
    const publicKeyHex = bytesToHex(pubKey);

    const bundle = await composeBundle(receipts, 'test-gateway', publicKeyHex, 'policy-ref');
    expect(bundle.receipts.length).toBe(10);
    expect(bundle.merkle_proofs.length).toBe(10);
    expect(bundle.merkle_root).toBeDefined();
    expect(bundle.algorithm).toBe('Ed25519-SHA256-JCS');

    const result = await verifyBundle(bundle);
    expect(result.algorithm_valid).toBe(true);
    expect(result.receipt_signatures_valid).toBe(true);
    expect(result.chain_integrity_valid).toBe(true);
    expect(result.merkle_proofs_valid).toBe(true);
    expect(result.bundle_consistent).toBe(true);
    expect(result.overall_valid).toBe(true);
    expect(result.receipts_checked).toBe(10);
  });

  it('should detect tampered receipt reason (signature fail)', async () => {
    const receipts = await generateReceiptChain(5);
    const pubKey = await getPublicKey(TEST_SEED);
    const publicKeyHex = bytesToHex(pubKey);

    const bundle = await composeBundle(receipts, 'test-gateway', publicKeyHex, 'policy-ref');

    // Tamper with a receipt's reason
    bundle.receipts[2] = { ...bundle.receipts[2], reason: 'tampered reason' };

    const result = await verifyBundle(bundle);
    expect(result.receipt_signatures_valid).toBe(false);
    expect(result.overall_valid).toBe(false);
  });

  it('should detect tampered previous_receipt_hash (chain fail)', async () => {
    const receipts = await generateReceiptChain(5);
    const pubKey = await getPublicKey(TEST_SEED);
    const publicKeyHex = bytesToHex(pubKey);

    const bundle = await composeBundle(receipts, 'test-gateway', publicKeyHex, 'policy-ref');

    // Swap receipt order to break chain
    const temp = bundle.receipts[1];
    bundle.receipts[1] = bundle.receipts[2];
    bundle.receipts[2] = temp;

    const result = await verifyBundle(bundle);
    expect(result.chain_integrity_valid).toBe(false);
    expect(result.overall_valid).toBe(false);
  });

  it('should detect tampered Merkle sibling (merkle fail)', async () => {
    const receipts = await generateReceiptChain(4);
    const pubKey = await getPublicKey(TEST_SEED);
    const publicKeyHex = bytesToHex(pubKey);

    const bundle = await composeBundle(receipts, 'test-gateway', publicKeyHex, 'policy-ref');

    // Tamper with a Merkle proof sibling
    if (bundle.merkle_proofs[0].siblings.length > 0) {
      bundle.merkle_proofs[0].siblings[0] = 'ff'.repeat(32);
    }

    const result = await verifyBundle(bundle);
    expect(result.merkle_proofs_valid).toBe(false);
    expect(result.overall_valid).toBe(false);
  });

  it('should verify a single-receipt bundle', async () => {
    const receipts = await generateReceiptChain(1);
    const pubKey = await getPublicKey(TEST_SEED);
    const publicKeyHex = bytesToHex(pubKey);

    const bundle = await composeBundle(receipts, 'test-gateway', publicKeyHex, 'policy-ref');
    expect(bundle.receipts.length).toBe(1);
    expect(bundle.merkle_proofs.length).toBe(1);

    const result = await verifyBundle(bundle);
    expect(result.overall_valid).toBe(true);
  });

  it('should reject unknown algorithm', async () => {
    const receipts = await generateReceiptChain(2);
    const pubKey = await getPublicKey(TEST_SEED);
    const publicKeyHex = bytesToHex(pubKey);

    const bundle = await composeBundle(receipts, 'test-gateway', publicKeyHex, 'policy-ref');

    // Change algorithm to unknown
    bundle.algorithm = 'RSA-PKCS1-SHA1';

    const result = await verifyBundle(bundle);
    expect(result.algorithm_valid).toBe(false);
    expect(result.overall_valid).toBe(false);
    expect(result.error).toContain('unsupported algorithm');
  });

  it('should reject bundle with mismatched proof count', async () => {
    const receipts = await generateReceiptChain(3);
    const pubKey = await getPublicKey(TEST_SEED);
    const publicKeyHex = bytesToHex(pubKey);

    const bundle = await composeBundle(receipts, 'test-gateway', publicKeyHex, 'policy-ref');

    // Remove a proof
    bundle.merkle_proofs.pop();

    const result = await verifyBundle(bundle);
    expect(result.bundle_consistent).toBe(false);
    expect(result.overall_valid).toBe(false);
  });
});
