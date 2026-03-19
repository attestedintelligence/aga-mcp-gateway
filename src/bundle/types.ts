// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP governance receipts
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { GovernanceReceipt } from '../receipt/types.js';

export interface EvidenceBundle {
  schema_version: string;
  bundle_id: string;
  algorithm: string;
  generated_at: string;
  gateway_id: string;
  public_key: string;
  policy_reference: string;
  receipts: GovernanceReceipt[];
  merkle_root: string;
  merkle_proofs: MerkleProof[];
  offline_capable: boolean;
}

export interface MerkleProof {
  leaf_hash: string;
  leaf_index: number;
  siblings: string[];
  directions: ('left' | 'right')[];
  merkle_root: string;
}

export interface VerificationResult {
  algorithm_valid: boolean;
  receipt_signatures_valid: boolean;
  chain_integrity_valid: boolean;
  merkle_proofs_valid: boolean;
  bundle_consistent: boolean;
  overall_valid: boolean;
  receipts_checked: number;
  algorithm: string;
  error?: string;
}
