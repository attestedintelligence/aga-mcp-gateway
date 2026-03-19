// AGA MCP Gateway - Durable Object Receipt Chain
// Reference implementation for MCP SEP-XXXX
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { GovernanceReceipt } from '../receipt/model.js';
import { computeReceiptHash } from '../receipt/chain.js';

/**
 * Durable Object class for persistent receipt chain storage.
 * Deployed to Cloudflare Workers. Unit tests use MemoryReceiptChain.
 */
export class ReceiptChainDO {
  private state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    switch (url.pathname) {
      case '/append':
        return this.handleAppend(request);
      case '/chain':
        return this.handleGetChain(request);
      case '/head':
        return this.handleGetHead();
      default:
        return new Response('Not Found', { status: 404 });
    }
  }

  private async handleAppend(request: Request): Promise<Response> {
    const receipt = await request.json() as GovernanceReceipt;
    const length = (await this.state.storage.get<number>('meta:length')) || 0;
    const headHash = (await this.state.storage.get<string>('meta:head_hash')) || '';

    // Idempotency check
    if (receipt.request_id !== null) {
      const key = `seen:${receipt.gateway_id}:${receipt.request_id}`;
      const existing = await this.state.storage.get<number>(key);
      if (existing !== undefined) {
        return Response.json({ sequence: existing, receipt_hash: headHash, idempotent: true });
      }
    }

    // Verify chain link
    if (receipt.previous_receipt_hash !== headHash) {
      return new Response('Conflict: previous_receipt_hash mismatch', { status: 409 });
    }

    // Compute receipt hash (SHA-256 of canonical receipt WITH signature)
    const receiptHash = await computeReceiptHash(receipt);

    // Atomic transaction
    await this.state.storage.transaction(async (txn) => {
      await txn.put(`receipt:${length}`, receipt);
      await txn.put('meta:length', length + 1);
      await txn.put('meta:head_hash', receiptHash);
      if (receipt.request_id !== null) {
        await txn.put(`seen:${receipt.gateway_id}:${receipt.request_id}`, length);
      }
    });

    return Response.json({ sequence: length, receipt_hash: receiptHash });
  }

  private async handleGetChain(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const from = parseInt(url.searchParams.get('from') || '0');
    const to = parseInt(url.searchParams.get('to') || '999999');
    const length = (await this.state.storage.get<number>('meta:length')) || 0;

    const receipts: GovernanceReceipt[] = [];
    const end = Math.min(to, length);
    for (let i = from; i < end; i++) {
      const receipt = await this.state.storage.get<GovernanceReceipt>(`receipt:${i}`);
      if (receipt) receipts.push(receipt);
    }

    return Response.json(receipts);
  }

  private async handleGetHead(): Promise<Response> {
    const length = (await this.state.storage.get<number>('meta:length')) || 0;
    const headHash = (await this.state.storage.get<string>('meta:head_hash')) || '';
    return Response.json({ length, head_hash: headHash });
  }
}
