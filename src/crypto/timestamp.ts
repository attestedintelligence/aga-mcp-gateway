// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP governance receipts
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Normalize an ISO 8601 timestamp to the AGA canonical form:
 * - Convert any timezone offset to UTC (Z suffix)
 * - Strip trailing ".000" (all-zero) sub-seconds
 * - Preserve non-zero sub-seconds but strip trailing zeros
 * - Always use "Z" suffix, never "+00:00"
 */
export function normalizeTimestamp(ts: string): string {
  // Parse the timestamp into a Date to handle timezone conversion
  const date = new Date(ts);

  // Extract components in UTC
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, '0');
  const day = String(date.getUTCDate()).padStart(2, '0');
  const hours = String(date.getUTCHours()).padStart(2, '0');
  const minutes = String(date.getUTCMinutes()).padStart(2, '0');
  const seconds = String(date.getUTCSeconds()).padStart(2, '0');

  let result = `${year}-${month}-${day}T${hours}:${minutes}:${seconds}`;

  // Handle sub-second precision from the original string
  // We need to extract sub-seconds from the original input, not from Date
  // (Date only has millisecond precision)
  const subSecondMatch = ts.match(/\.(\d+)/);
  if (subSecondMatch) {
    const subSeconds = subSecondMatch[1];
    // Strip trailing zeros
    const trimmed = subSeconds.replace(/0+$/, '');
    if (trimmed.length > 0) {
      result += '.' + trimmed;
    }
  }

  result += 'Z';
  return result;
}
