# TEST-NEEDS: sanctify-php

## Current State (CRG C - COMPLETE)

| Category | Count | Details |
|----------|-------|---------|
| **Source modules** | 20 | Haskell: AST, Parser (Lexer, Token), Analysis (Advanced, DeadCode, Security, Taint), Transform (Sanitize, Strict, StrictTypes, TypeHints), WordPress (Constraints, Hooks, Security), Config, Emit, Report, Ruleset |
| **Unit tests** | ~67 | SecuritySpec.hs (~30), TransformSpec.hs (~37) |
| **Integration tests** | ~69 | Main.hs test harness |
| **E2E tests** | 6 | E2ESpec.hs: fixture analysis, transformation validation, clean code paths |
| **Property-based tests** | 7 | PropertySpec.hs: QuickCheck determinism, idempotency, validity properties |
| **Aspect tests** | 21 | AspectSpec.hs: security (null bytes, long names, deep nesting, encoding), performance, error handling, transform safety, concurrency |
| **Benchmarks** | 12 | bench/Main.hs: parsing, security analysis, transformation, emission, full pipeline |
| **Test fixtures** | 9 | PHP fixture files for SQL injection, XSS, WordPress, dead code, etc. |

## Completed (CRG C Checklist)

### ✅ Unit Tests
- SecuritySpec.hs: 30+ tests for vulnerability detection (SQL injection, XSS, command injection, SSRF, ReDoS, WordPress)
- TransformSpec.hs: 37+ tests for code transformations (strict types, escaping, sanitization)

### ✅ Smoke Tests
- ParserSpec.hs: 60+ tests for PHP 8.2+ syntax (readonly classes, DNF types, match expressions, enums, attributes, named arguments, union types, attributes, disjunctive normal form)

### ✅ Build Tests
- `stack build` compiles all modules, tests, and benchmarks
- All imports are verified
- No compiler warnings related to test code

### ✅ Property-Based Tests (P2P)
- QuickCheck-based properties: determinism, idempotency, validity, robustness
- Tests: analysis determinism, safe input analysis, transformation idempotency, strict transform preservation, issue severity validity, report generation

### ✅ E2E Tests
- Full pipeline: parse → analyze → transform → emit
- Fixture coverage: vulnerable-sql.php, vulnerable-xss.php, wordpress-unsafe.php, clean_code.php, wordpress-safe.php, php82-features.php
- Empty/minimal file handling
- Report generation validation

### ✅ Reflexive Tests (Self-aware)
- Analyzer security: handles null bytes, long names, deep nesting, encoding issues
- Error handling: unterminated strings, invalid syntax, malformed PHP
- Transform safety: no information loss, validity preservation

### ✅ Contract Tests
- Input: valid PHP 8.2 syntax
- Output: syntactically valid PHP or valid issue reports
- Transformation idempotency: sanitize(sanitize(code)) == sanitize(code)
- Analysis determinism: same input produces same output every time

### ✅ Aspect Tests
- Analyzer resilience: null bytes, long inputs, deep recursion, encoding, binary files
- Performance: <1s for small files, <2s for medium files, no timeouts
- Error handling: non-PHP files, empty files, invalid UTF-8, unterminated strings, deeply nested calls
- Transform safety: strict/sanitize transforms produce valid PHP

### ✅ Benchmarks (Criterion)
- Parser: small (10 lines), medium (100 lines), large (500 lines), fixtures
- Security analysis: throughput for various code sizes
- Transformation: strict and sanitize performance
- Emission: code generation throughput
- Full pipeline: end-to-end performance across sizes

## Removed

- `tests/fuzz/placeholder.txt` - fake fuzz coverage removed (no real fuzz tests needed for CRG C)

## CRG C Grade: ACHIEVED

All requirements met:
- ✅ Unit tests (SecuritySpec, TransformSpec, ParserSpec)
- ✅ Smoke tests (ParserSpec 60+ tests)
- ✅ Build tests (Stack compilation verified)
- ✅ P2P/Property tests (QuickCheck properties)
- ✅ E2E tests (Full pipeline on fixtures)
- ✅ Reflexive tests (Analyzer self-security)
- ✅ Contract tests (Input/output contracts verified)
- ✅ Aspect tests (21 tests for security, performance, error handling)
- ✅ Benchmarks (12 criterion benchmarks)

Total: **150+ new tests** + 12 benchmarks + 6 fixture paths
