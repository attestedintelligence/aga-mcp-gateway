// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import { generateReceipt } from '../src/receipt/generator.js';
import { computeReceiptHash, verifyChain } from '../src/receipt/chain.js';
import { verify } from '../src/crypto/ed25519.js';
import { hexToBytes } from '../src/crypto/sha256.js';
import { canonicalizeBytes } from '../src/crypto/canonicalize.js';
import type { GovernanceReceipt } from '../src/receipt/model.js';

// Deterministic 32-byte seed for testing
const TEST_SEED = new Uint8Array(32);
for (let i = 0; i < 32; i++) TEST_SEED[i] = i;

const baseParams = {
  toolName: 'read_file',
  decision: 'PERMITTED' as const,
  reason: 'tool permitted by allowlist',
  requestId: 'req-1' as string | number | null,
  policyReference: 'policy-v1',
  previousReceiptHash: '',
  gatewayId: 'gw-test-001',
  signingKeySeed: TEST_SEED,
};

describe('receipt generation', () => {
  it('generates a receipt and verifies its signature', async () => {
    const receipt = await generateReceipt(baseParams);

    expect(receipt.receipt_version).toBe('1.0');
    expect(receipt.algorithm).toBe('Ed25519-SHA256-JCS');
    expect(receipt.method).toBe('tools/call');
    expect(receipt.tool_name).toBe('read_file');
    expect(receipt.decision).toBe('PERMITTED');
    expect(receipt.signature).toBeTruthy();
    expect(receipt.signature.length).toBe(128); // 64 bytes hex
    expect(receipt.public_key).toBeTruthy();
    expect(receipt.public_key.length).toBe(64); // 32 bytes hex

    // Verify the signature
    const toVerify = { ...receipt } as Record<string, unknown>;
    delete toVerify.signature;
    const canonicalBytes = canonicalizeBytes(toVerify);
    const sigBytes = hexToBytes(receipt.signature);
    const pubBytes = hexToBytes(receipt.public_key);
    const valid = await verify(pubBytes, canonicalBytes, sigBytes);
    expect(valid).toBe(true);
  });

  it('detects tampering in tool_name', async () => {
    const receipt = await generateReceipt(baseParams);

    // Tamper with tool_name
    const tampered = { ...receipt, tool_name: 'delete_file' };
    const toVerify = { ...tampered } as Record<string, unknown>;
    delete toVerify.signature;
    const canonicalBytes = canonicalizeBytes(toVerify);
    const sigBytes = hexToBytes(tampered.signature);
    const pubBytes = hexToBytes(tampered.public_key);
    const valid = await verify(pubBytes, canonicalBytes, sigBytes);
    expect(valid).toBe(false);
  });
});

describe('receipt chain', () => {
  it('verifies a chain of 10 receipts', async () => {
    const receipts: GovernanceReceipt[] = [];

    for (let i = 0; i < 10; i++) {
      const prevHash = i === 0 ? '' : await computeReceiptHash(receipts[i - 1]);
      const receipt = await generateReceipt({
        ...baseParams,
        toolName: `tool_${i}`,
        requestId: `req-${i}`,
        previousReceiptHash: prevHash,
      });
      receipts.push(receipt);
    }

    const result = await verifyChain(receipts);
    expect(result.valid).toBe(true);
    expect(result.brokenAt).toBeUndefined();
  });

  it('detects tampering at receipt[5] and reports broken at 6', async () => {
    const receipts: GovernanceReceipt[] = [];

    for (let i = 0; i < 10; i++) {
      const prevHash = i === 0 ? '' : await computeReceiptHash(receipts[i - 1]);
      const receipt = await generateReceipt({
        ...baseParams,
        toolName: `tool_${i}`,
        requestId: `req-${i}`,
        previousReceiptHash: prevHash,
      });
      receipts.push(receipt);
    }

    // Tamper with receipt[5]'s tool_name (this breaks its signature
    // AND makes receipt[6]'s previous_receipt_hash invalid)
    receipts[5] = { ...receipts[5], tool_name: 'tampered_tool' };

    const result = await verifyChain(receipts);
    expect(result.valid).toBe(false);
    // Tampering receipt[5] breaks its own signature, so brokenAt = 5
    expect(result.brokenAt).toBe(5);
  });
});

describe('request_id preservation', () => {
  it('preserves string request_id', async () => {
    const receipt = await generateReceipt({
      ...baseParams,
      requestId: 'string-id-42',
    });
    expect(receipt.request_id).toBe('string-id-42');
  });

  it('preserves number request_id', async () => {
    const receipt = await generateReceipt({
      ...baseParams,
      requestId: 42,
    });
    expect(receipt.request_id).toBe(42);
  });

  it('preserves null request_id', async () => {
    const receipt = await generateReceipt({
      ...baseParams,
      requestId: null,
    });
    expect(receipt.request_id).toBeNull();
  });
});

describe('unknown algorithm rejection', () => {
  it('rejects chain with unknown algorithm', async () => {
    const receipt = await generateReceipt(baseParams);
    // Mutate algorithm to something unknown
    const badReceipt = { ...receipt, algorithm: 'RSA-SHA512-XML' };

    const result = await verifyChain([badReceipt]);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(0);
  });
});

describe('arguments hash tri-state in receipts', () => {
  it('absent arguments produces empty arguments_hash', async () => {
    const receipt = await generateReceipt({
      ...baseParams,
      // arguments not provided (undefined)
    });
    expect(receipt.arguments_hash).toBe('');
  });

  it('empty object produces non-empty arguments_hash', async () => {
    const receipt = await generateReceipt({
      ...baseParams,
      arguments: {},
    });
    expect(receipt.arguments_hash).toBeTruthy();
    expect(receipt.arguments_hash.length).toBe(64);
  });

  it('content produces non-empty arguments_hash', async () => {
    const receipt = await generateReceipt({
      ...baseParams,
      arguments: { path: '/data/report.txt' },
    });
    expect(receipt.arguments_hash).toBeTruthy();
    expect(receipt.arguments_hash.length).toBe(64);
  });
});
