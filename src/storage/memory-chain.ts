// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP governance receipts
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { GovernanceReceipt } from '../receipt/types.js';
import { sha256Hex } from '../crypto/sha256.js';
import { canonicalize } from '../crypto/canonicalize.js';

/**
 * In-memory receipt chain for testing and local development.
 * Production uses Durable Objects for persistence.
 */
export class MemoryReceiptChain {
  private receipts: GovernanceReceipt[] = [];
  private headHash: string = '';

  /**
   * Append a receipt to the chain.
   * Returns the sequence number and the hash of the appended receipt.
   */
  async append(receipt: GovernanceReceipt): Promise<{ sequence: number; receiptHash: string }> {
    const sequence = this.receipts.length;
    this.receipts.push(receipt);
    this.headHash = receipt.receipt_hash;
    return { sequence, receiptHash: receipt.receipt_hash };
  }

  /**
   * Retrieve receipts within an optional range [from, to).
   * If no range is given, returns all receipts.
   */
  async getReceipts(from?: number, to?: number): Promise<GovernanceReceipt[]> {
    if (from !== undefined && to !== undefined) {
      return this.receipts.slice(from, to);
    }
    if (from !== undefined) {
      return this.receipts.slice(from);
    }
    return [...this.receipts];
  }

  /**
   * Get the current head of the chain.
   */
  async getHead(): Promise<{ length: number; headHash: string }> {
    return { length: this.receipts.length, headHash: this.headHash };
  }
}
