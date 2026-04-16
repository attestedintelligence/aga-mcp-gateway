// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import { getPublicKey, sign, verify } from '../src/crypto/ed25519.js';
import {
  sha256Hex, hexToBytes, bytesToHex, writeField, sha256Fields,
} from '../src/crypto/sha256.js';
import vectors from './vectors/aga_test_vectors.json';

const ed25519Data = vectors.ed25519_test_data;

describe('Ed25519', () => {
  const seed = hexToBytes(ed25519Data.seed_hex);
  const message = new TextEncoder().encode(ed25519Data.test_message_utf8);

  it('should derive a public key from a seed', async () => {
    const pubKey = await getPublicKey(seed);
    expect(pubKey).toBeInstanceOf(Uint8Array);
    expect(pubKey.length).toBe(32);
  });

  it('should produce a valid signature that verifies', async () => {
    const pubKey = await getPublicKey(seed);
    const sig = await sign(seed, message);
    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.length).toBe(64);
    const valid = await verify(pubKey, message, sig);
    expect(valid).toBe(true);
  });

  it('should produce deterministic signatures', async () => {
    const sig1 = await sign(seed, message);
    const sig2 = await sign(seed, message);
    expect(bytesToHex(sig1)).toBe(bytesToHex(sig2));
  });

  it('should reject tampered messages', async () => {
    const pubKey = await getPublicKey(seed);
    const sig = await sign(seed, message);
    const tampered = new Uint8Array(message);
    tampered[0] ^= 0xff;
    const valid = await verify(pubKey, tampered, sig);
    expect(valid).toBe(false);
  });

  it('should reject tampered signatures', async () => {
    const pubKey = await getPublicKey(seed);
    const sig = await sign(seed, message);
    const tamperedSig = new Uint8Array(sig);
    tamperedSig[0] ^= 0xff;
    const valid = await verify(pubKey, message, tamperedSig);
    expect(valid).toBe(false);
  });
});

describe('SHA-256', () => {
  it('should compute known hash of empty input', async () => {
    const hash = await sha256Hex(new Uint8Array(0));
    expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('should compute known hash of "abc"', async () => {
    const hash = await sha256Hex(new TextEncoder().encode('abc'));
    expect(hash).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('should compute correct hash for the ed25519 test message', async () => {
    const hash = await sha256Hex(new TextEncoder().encode(ed25519Data.test_message_utf8));
    expect(hash).toBe(ed25519Data.test_message_sha256);
  });
});

describe('hexToBytes / bytesToHex', () => {
  it('should round-trip correctly', () => {
    const hex = 'deadbeef0123456789abcdef';
    const bytes = hexToBytes(hex);
    expect(bytesToHex(bytes)).toBe(hex);
  });

  it('should handle empty input', () => {
    expect(bytesToHex(hexToBytes(''))).toBe('');
  });
});

describe('writeField', () => {
  it('should produce 4-byte big-endian length prefix', () => {
    const data = new TextEncoder().encode('abc');
    const field = writeField(data);
    expect(field.length).toBe(4 + 3);
    // Length prefix: 0x00000003
    expect(field[0]).toBe(0);
    expect(field[1]).toBe(0);
    expect(field[2]).toBe(0);
    expect(field[3]).toBe(3);
    // Data
    expect(field[4]).toBe(0x61); // 'a'
    expect(field[5]).toBe(0x62); // 'b'
    expect(field[6]).toBe(0x63); // 'c'
  });

  it('should handle empty data', () => {
    const field = writeField(new Uint8Array(0));
    expect(field.length).toBe(4);
    expect(field[0]).toBe(0);
    expect(field[1]).toBe(0);
    expect(field[2]).toBe(0);
    expect(field[3]).toBe(0);
  });
});

describe('sha256Fields', () => {
  it('should match leaf hash vectors', async () => {
    const encoder = new TextEncoder();
    for (const vec of vectors.leaf_hash_vectors) {
      const { inputs, expected_leaf_hash_hex } = vec;
      const hash = await sha256Fields(
        encoder.encode(inputs.schema_version),
        encoder.encode(inputs.protocol_version),
        encoder.encode(inputs.event_type),
        encoder.encode(inputs.event_id),
        encoder.encode(inputs.sequence_number.toString()),
        encoder.encode(inputs.timestamp),
        hexToBytes(inputs.previous_leaf_hash_hex),
      );
      expect(hash).toBe(expected_leaf_hash_hex);
    }
  });
});
