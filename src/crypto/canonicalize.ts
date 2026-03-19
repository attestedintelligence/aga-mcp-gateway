// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 * Produces deterministic JSON output with sorted keys and
 * ECMAScript-compliant number serialization.
 */
export function canonicalize(value: unknown): string {
  return serializeValue(value);
}

function serializeValue(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return serializeNumber(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(serializeValue).join(',') + ']';
  if (typeof value === 'object') return serializeObject(value as Record<string, unknown>);
  throw new Error('unsupported type: ' + typeof value);
}

/**
 * Serialize a number per RFC 8785 rules:
 * - Negative zero becomes positive zero
 * - Non-finite values are rejected
 * - Otherwise use ECMAScript Number.toString() output
 */
function serializeNumber(n: number): string {
  if (Object.is(n, -0)) return '0';
  if (!isFinite(n)) throw new Error('non-finite number');
  // ECMAScript Number.toString() matches RFC 8785 requirements
  return JSON.stringify(n);
}

/**
 * Serialize an object with keys sorted by Unicode code point order (RFC 8785).
 */
function serializeObject(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort();
  const pairs = keys.map(k => JSON.stringify(k) + ':' + serializeValue(obj[k]));
  return '{' + pairs.join(',') + '}';
}

/**
 * Canonicalize a value and return as UTF-8 bytes.
 */
export function canonicalizeBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
