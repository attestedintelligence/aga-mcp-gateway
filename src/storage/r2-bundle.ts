// AGA MCP Gateway - R2 Evidence Bundle Storage
// Reference implementation for MCP SEP-XXXX
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Store an evidence bundle to R2.
 */
export async function storeBundleToR2(
  bucket: R2Bucket,
  bundleId: string,
  bundleJson: string,
): Promise<void> {
  await bucket.put(`bundles/${bundleId}.json`, bundleJson, {
    customMetadata: { generated_at: new Date().toISOString() },
  });
}

/**
 * Retrieve an evidence bundle from R2 by ID.
 */
export async function getBundleFromR2(
  bucket: R2Bucket,
  bundleId: string,
): Promise<string | null> {
  const obj = await bucket.get(`bundles/${bundleId}.json`);
  if (!obj) return null;
  return obj.text();
}

/**
 * List all bundle IDs stored in R2.
 */
export async function listBundles(
  bucket: R2Bucket,
): Promise<string[]> {
  const list = await bucket.list({ prefix: 'bundles/' });
  return list.objects.map(o => o.key.replace('bundles/', '').replace('.json', ''));
}
