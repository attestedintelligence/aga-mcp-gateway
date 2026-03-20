// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { GovernanceReceipt } from '../receipt/model.js';

/**
 * Common interface for receipt chain storage.
 * Implemented by both DurableObjectChainClient (production)
 * and MemoryReceiptChain (tests).
 */
export interface ReceiptChain {
  append(receipt: GovernanceReceipt): Promise<{ sequence: number; receiptHash: string; conflict?: boolean }>;
  getHead(): Promise<{ length: number; headHash: string }>;
  getReceipts(from?: number, to?: number): Promise<GovernanceReceipt[]>;
}

/**
 * Client that proxies chain operations to the ReceiptChainDO
 * Durable Object via internal fetch calls.
 */
export class DurableObjectChainClient implements ReceiptChain {
  private stub: DurableObjectStub;

  constructor(ns: DurableObjectNamespace, gatewayId: string) {
    const id = ns.idFromName(gatewayId);
    this.stub = ns.get(id);
  }

  async append(receipt: GovernanceReceipt): Promise<{ sequence: number; receiptHash: string; conflict?: boolean }> {
    const resp = await this.stub.fetch('https://do/append', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(receipt),
    });

    if (resp.status === 409) {
      return { sequence: -1, receiptHash: '', conflict: true };
    }

    const data = await resp.json() as { sequence: number; receipt_hash: string; idempotent?: boolean };
    return { sequence: data.sequence, receiptHash: data.receipt_hash };
  }

  async getHead(): Promise<{ length: number; headHash: string }> {
    const resp = await this.stub.fetch('https://do/head');
    const data = await resp.json() as { length: number; head_hash: string };
    return { length: data.length, headHash: data.head_hash };
  }

  async getReceipts(from?: number, to?: number): Promise<GovernanceReceipt[]> {
    const params = new URLSearchParams();
    if (from !== undefined) params.set('from', String(from));
    if (to !== undefined) params.set('to', String(to));
    const url = `https://do/chain${params.toString() ? '?' + params.toString() : ''}`;
    const resp = await this.stub.fetch(url);
    return await resp.json() as GovernanceReceipt[];
  }
}
