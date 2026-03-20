// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { GovernanceReceipt } from '../receipt/model.js';
import type { ReceiptChain } from './chain-client.js';
import { computeReceiptHash } from '../receipt/chain.js';

/**
 * In-memory receipt chain for testing and local development.
 * Production uses Durable Objects for persistence.
 */
export class MemoryReceiptChain implements ReceiptChain {
  private receipts: GovernanceReceipt[] = [];
  private headHash: string = '';

  /**
   * Append a receipt to the chain.
   * Computes chain hash as SHA-256(canonicalize(receipt WITH signature))
   * per directive Section 3.3.
   *
   * Returns conflict: true if previous_receipt_hash does not match head.
   */
  async append(receipt: GovernanceReceipt): Promise<{ sequence: number; receiptHash: string; conflict?: boolean }> {
    // Verify chain linkage
    if (receipt.previous_receipt_hash !== this.headHash) {
      return { sequence: -1, receiptHash: this.headHash, conflict: true };
    }

    const sequence = this.receipts.length;
    this.receipts.push(receipt);
    this.headHash = await computeReceiptHash(receipt);
    return { sequence, receiptHash: this.headHash };
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
