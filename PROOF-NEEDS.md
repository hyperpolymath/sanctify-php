# PROOF-NEEDS.md
<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->

## Current State

- **LOC**: ~9,400
- **Languages**: Haskell, Idris2, Zig
- **Existing ABI proofs**: `src/abi/*.idr` (template-level)
- **Dangerous patterns**: None detected in Haskell source

## What Needs Proving

### Taint Analysis (src/Sanctify/Analysis/Taint.hs)
- Tracks tainted data flow through PHP code
- Prove: taint propagation is sound (no tainted value reaches a sink without sanitization)
- This is the security-critical core of the tool

### Security Analysis (src/Sanctify/Analysis/Security.hs)
- Detects security vulnerabilities in PHP
- Prove: analysis does not have false negatives for the declared vulnerability classes

### Dead Code Analysis (src/Sanctify/Analysis/DeadCode.hs)
- Prove: reported dead code is genuinely unreachable

### Type Checker (src/Sanctify/Analysis/Types.hs)
- PHP type inference
- Prove: type inference is sound with respect to PHP runtime semantics

### Parser Correctness (src/Sanctify/Parser/)
- `Parser.hs`, `Lexer.hs`, `Token.hs`
- Prove: parser accepts valid PHP and rejects invalid PHP (or at minimum, is conservative)

### Transform Soundness (src/Sanctify/Transform/)
- `Sanitize.hs`, `Strict.hs`, `StrictTypes.hs`, `TypeHints.hs`
- Prove: code transformations preserve program semantics
- Prove: sanitization transforms eliminate the security vulnerabilities they claim to fix

### WordPress-Specific Rules (src/Sanctify/WordPress/)
- `Constraints.hs`, `Hooks.hs`, `Security.hs`
- Prove: WordPress hook analysis correctly models WordPress execution order

## Recommended Prover

- **Agda** or **Lean4** — Haskell analysis tools have a strong tradition of formal verification
- **Idris2** for ABI contracts

## Priority

**HIGH** — Security analysis tool. If the taint analysis is unsound, users trust code that is actually vulnerable. False negatives in a security tool are worse than no tool at all.
