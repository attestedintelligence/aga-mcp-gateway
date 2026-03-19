// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import { canonicalize, canonicalizeBytes } from '../src/crypto/canonicalize.js';
import { sha256Hex, bytesToHex } from '../src/crypto/sha256.js';
import vectors from './vectors/aga_test_vectors.json';

describe('Canonicalization - RFC 8785 vectors', () => {
  for (const vec of vectors.canonicalization_vectors) {
    it(`should match vector: ${vec.id}`, async () => {
      const canonical = canonicalize(vec.input_json);
      expect(canonical).toBe(vec.expected_canonical_string);

      // Verify SHA-256 of canonical form
      const bytes = new TextEncoder().encode(canonical);
      const hash = await sha256Hex(bytes);
      expect(hash).toBe(vec.expected_sha256);

      // Verify hex encoding if provided
      if ('expected_canonical_hex' in vec) {
        expect(bytesToHex(bytes)).toBe(
          (vec as Record<string, unknown>).expected_canonical_hex
        );
      }
    });
  }
});

describe('canonicalizeBytes', () => {
  it('should return UTF-8 encoding of canonical JSON', () => {
    const input = { z: 1, a: 2 };
    const bytes = canonicalizeBytes(input);
    const str = new TextDecoder().decode(bytes);
    expect(str).toBe('{"a":2,"z":1}');
  });
});
