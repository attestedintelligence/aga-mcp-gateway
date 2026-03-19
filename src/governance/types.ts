// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP governance receipts
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

export interface ToolConstraint {
  name: string;
  allowed: boolean;
  max_calls_per_minute?: number;
  requires_approval?: boolean;
  path_prefix?: string;
  path_keys?: string[];
  denied_patterns?: string[];
}

export interface ToolPolicy {
  mode: 'allowlist' | 'denylist' | 'audit_only';
  constraints: Record<string, ToolConstraint>;
}

export interface ToolCallDecision {
  allowed: boolean;
  reason: string;
  tool_name: string;
  policy_mode: string;
}
