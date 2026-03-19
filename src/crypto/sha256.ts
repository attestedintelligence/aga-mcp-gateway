// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Compute SHA-256 hash of raw bytes using the Web Crypto API.
 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

/**
 * Compute SHA-256 hash and return as lowercase hex string.
 */
export async function sha256Hex(data: Uint8Array): Promise<string> {
  const hash = await sha256(data);
  return bytesToHex(hash);
}

/**
 * Convert a hex string to a Uint8Array of bytes.
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert a Uint8Array to a lowercase hex string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Encode a field as a 4-byte big-endian length prefix followed by the data.
 * This matches the Go writeField implementation for domain separation.
 */
export function writeField(data: Uint8Array): Uint8Array {
  const len = new DataView(new ArrayBuffer(4));
  len.setUint32(0, data.length, false); // big-endian
  const result = new Uint8Array(4 + data.length);
  result.set(new Uint8Array(len.buffer), 0);
  result.set(data, 4);
  return result;
}

/**
 * Concatenate length-prefixed fields, then SHA-256 hash the result.
 * Returns the hash as a lowercase hex string.
 */
export async function sha256Fields(...fields: Uint8Array[]): Promise<string> {
  let total = 0;
  const prefixed = fields.map(f => writeField(f));
  for (const p of prefixed) total += p.length;
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const p of prefixed) {
    combined.set(p, offset);
    offset += p.length;
  }
  return sha256Hex(combined);
}
