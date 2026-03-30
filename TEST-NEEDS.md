# TEST-NEEDS: sanctify-php

## Current State

| Category | Count | Details |
|----------|-------|---------|
| **Source modules** | 20 | Haskell: AST, Parser (Lexer, Token), Analysis (Advanced, DeadCode, Security, Taint), Transform (Sanitize, Strict, StrictTypes, TypeHints), WordPress (Constraints, Hooks, Security), Config, Emit, Report, Ruleset |
| **Unit tests** | ~67 | SecuritySpec.hs (~30), TransformSpec.hs (~37) |
| **Integration tests** | ~69 | Main.hs test harness |
| **E2E tests** | 0 | No end-to-end with actual PHP files through full pipeline |
| **Test fixtures** | 9 | PHP fixture files for SQL injection, XSS, WordPress, dead code, etc. |
| **Benchmarks** | 0 | None |

## What's Missing

### E2E Tests
- [ ] No test that runs sanctify-php as a binary on a PHP codebase
- [ ] No test that validates transformed PHP output is syntactically valid

### Aspect Tests
- [ ] **Security**: SecuritySpec exists but only ~30 tests for a SECURITY ANALYSIS TOOL. Needs 200+
- [ ] **Performance**: No tests for large PHP codebases (1000+ files)
- [ ] **Concurrency**: No parallel analysis tests
- [ ] **Error handling**: No tests for malformed PHP, encoding issues, huge files

### Benchmarks Needed
- [ ] Parsing throughput (lines/second on real WordPress codebases)
- [ ] Taint analysis scaling with codebase size
- [ ] Memory usage on large projects

### Self-Tests
- [ ] No self-diagnostic mode

## FLAGGED ISSUES
- **A security analysis tool with ~30 security tests** is embarrassing. This needs an order of magnitude more.
- **Taint analysis module has 0 dedicated tests** -- the most critical analysis capability is untested
- **Dead code detection has 0 dedicated tests** (only fixture files exist)

## Priority: P1 (HIGH)

## FAKE-FUZZ ALERT

- `tests/fuzz/placeholder.txt` is a scorecard placeholder inherited from rsr-template-repo — it does NOT provide real fuzz testing
- Replace with an actual fuzz harness (see rsr-template-repo/tests/fuzz/README.adoc) or remove the file
- Priority: P2 — creates false impression of fuzz coverage
