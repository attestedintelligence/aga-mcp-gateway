// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP governance receipts
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import * as ed from '@noble/ed25519';

/**
 * Derive an Ed25519 public key from a 32-byte seed (secret key).
 */
export async function getPublicKey(seed: Uint8Array): Promise<Uint8Array> {
  return ed.getPublicKeyAsync(seed);
}

/**
 * Sign a message with a 32-byte Ed25519 seed.
 * Returns a 64-byte signature.
 */
export async function sign(seed: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  return ed.signAsync(message, seed);
}

/**
 * Verify an Ed25519 signature against a public key and message.
 * Returns true if valid, false otherwise.
 */
export async function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  try {
    return await ed.verifyAsync(signature, message, publicKey);
  } catch {
    return false;
  }
}
