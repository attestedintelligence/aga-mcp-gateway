// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

export interface GovernanceReceipt {
  receipt_id: string;
  receipt_version: string;
  algorithm: string;
  timestamp: string;
  request_id: string | number | null;
  method: string;
  tool_name: string;
  decision: 'PERMITTED' | 'DENIED';
  reason: string;
  policy_reference: string;
  arguments_hash: string;
  previous_receipt_hash: string;
  gateway_id: string;
  signature: string;
  public_key: string;
}
