// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

export interface Env {
  GATEWAY_ID: string;
  UPSTREAM_URL: string;
  SEALED_POLICY: string;
  SIGNING_KEY_SEED: string;
  RECEIPT_CHAIN: DurableObjectNamespace;
  BUNDLES: R2Bucket;
}
