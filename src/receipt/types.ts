// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP governance receipts
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

export interface GovernanceReceipt {
  schema_version: string;
  receipt_id: string;
  gateway_id: string;
  timestamp: string;
  sequence_number: number;
  tool_name: string;
  arguments_hash: string;
  decision: string;
  reason: string;
  policy_hash: string;
  request_id: string;
  previous_receipt_hash: string;
  receipt_hash: string;
  signature: string;
  public_key: string;
}
