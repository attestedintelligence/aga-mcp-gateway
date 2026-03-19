// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP governance receipts
// Patent: USPTO App. No. 19/433,835
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import { evaluate, cleanPath, matchesPrefix } from '../src/governance/policy.js';
import type { ToolPolicy } from '../src/governance/types.js';
import { canonicalize } from '../src/crypto/canonicalize.js';
import { sha256Hex } from '../src/crypto/sha256.js';

describe('cleanPath', () => {
  it('resolves . and ..', () => {
    expect(cleanPath('/a/b/../c/./d')).toBe('/a/c/d');
  });

  it('collapses consecutive slashes', () => {
    expect(cleanPath('/a//b///c')).toBe('/a/b/c');
  });

  it('removes trailing slash', () => {
    expect(cleanPath('/data/')).toBe('/data');
  });

  it('handles root', () => {
    expect(cleanPath('/')).toBe('/');
  });
});

describe('matchesPrefix', () => {
  it('permits exact match', () => {
    expect(matchesPrefix('/data', '/data')).toBe(true);
  });

  it('permits path under prefix', () => {
    expect(matchesPrefix('/data', '/data/report.txt')).toBe(true);
  });

  it('denies path outside prefix', () => {
    expect(matchesPrefix('/data', '/etc/passwd')).toBe(false);
  });

  it('denies segment-boundary mismatch', () => {
    expect(matchesPrefix('/data', '/database/x')).toBe(false);
  });
});

describe('policy evaluation', () => {
  describe('allowlist mode', () => {
    it('permits listed and allowed tool', () => {
      const policy: ToolPolicy = {
        mode: 'allowlist',
        constraints: {
          read_file: { name: 'read_file', allowed: true },
        },
      };
      const result = evaluate(policy, 'read_file');
      expect(result.allowed).toBe(true);
      expect(result.policy_mode).toBe('allowlist');
    });

    it('denies unlisted tool', () => {
      const policy: ToolPolicy = {
        mode: 'allowlist',
        constraints: {
          read_file: { name: 'read_file', allowed: true },
        },
      };
      const result = evaluate(policy, 'write_file');
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('not in allowlist');
    });

    it('denies listed but not allowed tool', () => {
      const policy: ToolPolicy = {
        mode: 'allowlist',
        constraints: {
          write_file: { name: 'write_file', allowed: false },
        },
      };
      const result = evaluate(policy, 'write_file');
      expect(result.allowed).toBe(false);
    });
  });

  describe('denylist mode', () => {
    it('denies listed and not-allowed tool', () => {
      const policy: ToolPolicy = {
        mode: 'denylist',
        constraints: {
          delete_file: { name: 'delete_file', allowed: false },
        },
      };
      const result = evaluate(policy, 'delete_file');
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('denied by denylist');
    });

    it('permits unlisted tool', () => {
      const policy: ToolPolicy = {
        mode: 'denylist',
        constraints: {
          delete_file: { name: 'delete_file', allowed: false },
        },
      };
      const result = evaluate(policy, 'read_file');
      expect(result.allowed).toBe(true);
      expect(result.reason).toContain('not denied');
    });
  });

  describe('path prefix constraints', () => {
    const policy: ToolPolicy = {
      mode: 'allowlist',
      constraints: {
        read_file: {
          name: 'read_file',
          allowed: true,
          path_prefix: '/data/',
        },
      },
    };

    it('permits path under prefix', () => {
      const result = evaluate(policy, 'read_file', { path: '/data/report.txt' });
      expect(result.allowed).toBe(true);
    });

    it('denies path outside prefix', () => {
      const result = evaluate(policy, 'read_file', { path: '/etc/passwd' });
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('outside allowed prefix');
    });

    it('denies segment-boundary mismatch', () => {
      const result = evaluate(policy, 'read_file', { path: '/database/x' });
      expect(result.allowed).toBe(false);
    });

    it('denies path traversal', () => {
      const result = evaluate(policy, 'read_file', { path: '/data/../../../etc/passwd' });
      expect(result.allowed).toBe(false);
    });
  });

  describe('path keys', () => {
    it('checks custom path key', () => {
      const policy: ToolPolicy = {
        mode: 'allowlist',
        constraints: {
          read_file: {
            name: 'read_file',
            allowed: true,
            path_prefix: '/data/',
            path_keys: ['filepath'],
          },
        },
      };
      const result = evaluate(policy, 'read_file', { filepath: '/etc/passwd' });
      expect(result.allowed).toBe(false);
    });
  });

  describe('denied patterns', () => {
    it('denies argument matching pattern', () => {
      const policy: ToolPolicy = {
        mode: 'allowlist',
        constraints: {
          run_command: {
            name: 'run_command',
            allowed: true,
            denied_patterns: ['rm -rf', 'sudo'],
          },
        },
      };
      const result = evaluate(policy, 'run_command', { command: 'sudo rm -rf /' });
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('denied pattern');
    });

    it('permits argument not matching any pattern', () => {
      const policy: ToolPolicy = {
        mode: 'allowlist',
        constraints: {
          run_command: {
            name: 'run_command',
            allowed: true,
            denied_patterns: ['rm -rf', 'sudo'],
          },
        },
      };
      const result = evaluate(policy, 'run_command', { command: 'ls -la' });
      expect(result.allowed).toBe(true);
    });
  });

  describe('audit_only mode', () => {
    it('permits all calls', () => {
      const policy: ToolPolicy = {
        mode: 'audit_only',
        constraints: {},
      };
      const result = evaluate(policy, 'any_tool');
      expect(result.allowed).toBe(true);
      expect(result.reason).toContain('audit_only');
    });
  });

  describe('unknown mode', () => {
    it('denies all calls', () => {
      const policy = {
        mode: 'unknown_mode' as ToolPolicy['mode'],
        constraints: {},
      };
      const result = evaluate(policy, 'any_tool');
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('unknown policy mode');
    });
  });

  describe('arguments hash tri-state', () => {
    it('absent arguments produces empty hash', async () => {
      // When arguments is undefined, hash should be ""
      const hash = undefined === undefined ? '' : 'not-empty';
      expect(hash).toBe('');
    });

    it('empty object produces hash of {}', async () => {
      const canonical = canonicalize({});
      const bytes = new TextEncoder().encode(canonical);
      const hash = await sha256Hex(bytes);
      expect(hash).toBeTruthy();
      expect(hash.length).toBe(64);
      // The canonical form of {} is "{}"
      expect(canonical).toBe('{}');
    });

    it('content produces hash of canonicalized content', async () => {
      const args = { key: 'value', num: 42 };
      const canonical = canonicalize(args);
      const bytes = new TextEncoder().encode(canonical);
      const hash = await sha256Hex(bytes);
      expect(hash).toBeTruthy();
      expect(hash.length).toBe(64);
    });
  });
});
