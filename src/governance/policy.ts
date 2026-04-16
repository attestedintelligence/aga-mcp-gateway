// AGA MCP Gateway - Cryptographic Governance Receipts
// Reference implementation for MCP SEP-XXXX
// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: Apache-2.0

import type { ToolPolicy, ToolCallDecision } from './types.js';

/**
 * POSIX-style path normalization.
 * Resolves . and .., collapses consecutive slashes,
 * removes trailing slash (unless root).
 */
export function cleanPath(p: string): string {
  // Normalize backslashes to forward slashes
  p = p.replace(/\\/g, '/');

  // Collapse consecutive slashes
  p = p.replace(/\/+/g, '/');

  const segments = p.split('/');
  const resolved: string[] = [];
  const absolute = segments[0] === '';

  for (const seg of segments) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (resolved.length > 0 && resolved[resolved.length - 1] !== '..') {
        resolved.pop();
      } else if (!absolute) {
        resolved.push('..');
      }
      // If absolute, skip .. that goes above root
    } else {
      resolved.push(seg);
    }
  }

  let result = (absolute ? '/' : '') + resolved.join('/');
  if (result === '') result = '.';
  return result;
}

/**
 * Segment-boundary prefix matching per directive Section 3.2.
 * The candidate path must either equal the prefix exactly or
 * diverge only at a segment boundary (a "/" character).
 */
export function matchesPrefix(prefix: string, candidate: string): boolean {
  const cleanPrefix = cleanPath(prefix);
  const cleanCandidate = cleanPath(candidate);

  if (cleanCandidate === cleanPrefix) return true;
  // Ensure prefix ends with / for segment-boundary check
  const prefixWithSlash = cleanPrefix.endsWith('/') ? cleanPrefix : cleanPrefix + '/';
  return cleanCandidate.startsWith(prefixWithSlash);
}

/**
 * Evaluate a tool call against a governance policy.
 * Matches Go tool_policy.go behavior.
 */
export function evaluate(
  policy: ToolPolicy,
  toolName: string,
  args?: Record<string, unknown>,
): ToolCallDecision {
  const base = { tool_name: toolName, policy_mode: policy.mode };

  // Audit-only mode: always permit
  if (policy.mode === 'audit_only') {
    return { ...base, allowed: true, reason: 'audit_only: all calls permitted' };
  }

  // Unknown mode: deny
  if (policy.mode !== 'allowlist' && policy.mode !== 'denylist') {
    return { ...base, allowed: false, reason: `unknown policy mode: ${policy.mode}` };
  }

  const constraint = policy.constraints[toolName];

  if (policy.mode === 'allowlist') {
    if (!constraint) {
      return { ...base, allowed: false, reason: 'tool not in allowlist' };
    }
    if (!constraint.allowed) {
      return { ...base, allowed: false, reason: 'tool explicitly disallowed' };
    }
    // Check path and pattern constraints
    const pathResult = checkPathConstraints(constraint, args);
    if (pathResult !== null) {
      return { ...base, allowed: false, reason: pathResult };
    }
    const patternResult = checkDeniedPatterns(constraint, args);
    if (patternResult !== null) {
      return { ...base, allowed: false, reason: patternResult };
    }
    return { ...base, allowed: true, reason: 'tool permitted by allowlist' };
  }

  // Denylist mode
  if (constraint && !constraint.allowed) {
    return { ...base, allowed: false, reason: 'tool denied by denylist' };
  }
  return { ...base, allowed: true, reason: 'tool not denied' };
}

/**
 * Check path_prefix constraints against argument values.
 * Returns an error reason string if denied, null if OK.
 */
function checkPathConstraints(
  constraint: { path_prefix?: string; path_keys?: string[] },
  args?: Record<string, unknown>,
): string | null {
  if (!constraint.path_prefix) return null;

  const keys = constraint.path_keys && constraint.path_keys.length > 0
    ? constraint.path_keys
    : ['path'];

  if (!args) return null;

  for (const key of keys) {
    const val = args[key];
    if (typeof val === 'string') {
      if (!matchesPrefix(constraint.path_prefix, val)) {
        return `path "${val}" outside allowed prefix "${constraint.path_prefix}"`;
      }
    }
  }

  return null;
}

/**
 * Check denied_patterns against all string argument values.
 * Returns an error reason string if a pattern matches, null if OK.
 */
function checkDeniedPatterns(
  constraint: { denied_patterns?: string[] },
  args?: Record<string, unknown>,
): string | null {
  if (!constraint.denied_patterns || constraint.denied_patterns.length === 0) return null;
  if (!args) return null;

  for (const [, val] of Object.entries(args)) {
    if (typeof val !== 'string') continue;
    for (const pattern of constraint.denied_patterns) {
      if (val.includes(pattern)) {
        return `argument value matches denied pattern "${pattern}"`;
      }
    }
  }

  return null;
}
