# AGA MCP Gateway: Build Plan

This is a new TypeScript project implementing the MCP receipt gateway
per the AGA_MCP_Gateway_Directive.md specification.

## Status

- [x] Project initialized (npm, git, directory structure)
- [x] Test vectors copied from aga-k8s (26 existing + 11 new)
- [x] Dependencies installed (@noble/ed25519, vitest, wrangler, typescript)
- [ ] Phase 1: Crypto foundation (ed25519, sha256, canonicalize)
- [ ] Phase 2: Policy evaluator + receipt generator + chain linking
- [ ] Phase 3: Streamable HTTP proxy + Durable Object
- [ ] Phase 4: Evidence bundle + cross-implementation verification

## Key Constraint

The Go codebase (aga-k8s) defines correct behavior. TypeScript MUST
produce identical outputs for identical inputs. The test vectors are
the interoperability contract. If Go and TypeScript disagree on any
vector, the TypeScript implementation is wrong.

## Execution

Each phase must pass its test suite before the next phase begins.
Phase 1 is the foundation. Everything depends on it.
