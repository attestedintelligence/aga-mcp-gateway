// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP governance receipts
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Create a JSON-RPC 2.0 error response for a denied tool call.
 * Uses error code -32600 (Invalid Request).
 */
export function makeDenyResponse(
  id: string | number | null,
  tool: string,
  reason: string,
  policyMode: string,
): string {
  const response = {
    jsonrpc: '2.0' as const,
    id,
    error: {
      code: -32600,
      message: `Tool "${tool}" denied by ${policyMode} policy: ${reason}`,
    },
  };
  return JSON.stringify(response);
}
