// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP governance receipts
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import { canonicalize } from '../src/crypto/canonicalize.js';
import { sha256Hex } from '../src/crypto/sha256.js';
import vectors from './vectors/aga_test_vectors.json';

describe('Canonicalization - edge vectors', () => {
  for (const vec of vectors.canonicalization_edge_vectors) {
    it(`should match edge vector: ${vec.id}`, async () => {
      const canonical = canonicalize(vec.input_json);
      expect(canonical).toBe(vec.expected_canonical_string);

      const bytes = new TextEncoder().encode(canonical);
      const hash = await sha256Hex(bytes);
      expect(hash).toBe(vec.expected_sha256);
    });
  }
});
