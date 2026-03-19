// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP governance receipts
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

export interface ParsedToolCall {
  method: string;
  id: string | number | null;
  toolName: string;
  arguments?: Record<string, unknown>;
}

/**
 * Parse a JSON-RPC 2.0 request body for tool call interception.
 *
 * - If method !== "tools/call": return null (forward transparently)
 * - Extract params.name, params.arguments, id
 * - If params.name missing/empty: return ParsedToolCall with toolName="UNKNOWN"
 */
export function parseToolCall(body: string): ParsedToolCall | null {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }

  // Must be a JSON-RPC 2.0 request
  if (typeof parsed !== 'object' || parsed === null) return null;

  const method = parsed.method;
  if (typeof method !== 'string') return null;

  // Only intercept tools/call
  if (method !== 'tools/call') return null;

  const id = parsed.id ?? null;
  const normalizedId = (typeof id === 'string' || typeof id === 'number') ? id : null;

  const params = parsed.params as Record<string, unknown> | undefined;
  const toolName = params && typeof params.name === 'string' && params.name !== ''
    ? params.name
    : 'UNKNOWN';

  const args = params && typeof params.arguments === 'object' && params.arguments !== null
    ? params.arguments as Record<string, unknown>
    : undefined;

  return {
    method,
    id: normalizedId,
    toolName,
    arguments: args,
  };
}
