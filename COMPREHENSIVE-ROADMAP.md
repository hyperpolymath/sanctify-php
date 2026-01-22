# Sanctify-PHP Comprehensive Implementation Roadmap
**Target: 40% → 100% Completion**
**Vision: Production-Ready PHP Security Analysis & Hardening Tool**

## Current Status Assessment (40%)

### ✅ Implemented (Strong Foundation)
- **AST**: Comprehensive PHP 8.x AST with modern features (attributes, enums, match, etc.)
- **Parser**: Megaparsec-based PHP parser (basic structures working)
- **Security Analysis**: Extensive vulnerability detection
  - SQL injection, XSS, CSRF, command injection
  - Path traversal, unsafe deserialization
  - Weak crypto (with modern recommendations: SHAKE3-256/BLAKE3)
  - Hardcoded secrets detection
  - Dangerous function flagging
- **Transform/Sanitize**: WordPress-specific security transformations
  - Output escaping (esc_html, esc_attr, etc.)
  - Input sanitization detection
  - SQL preparation wrapping
  - Superglobal sanitization
  - Exit after redirect
- **WordPress**: WordPress-specific constraint checking
- **Core Modules**: Config, Report, Ruleset (exist but need verification)

### ⚠️ Needs Completion/Enhancement (60% Gap)
1. **Parser**: Needs full PHP 8.x expression/statement coverage
2. **Emit**: PHP code generation from AST (critical for transformations)
3. **Taint Analysis**: Data flow tracking needs completion
4. **Type Inference**: PHP type system inference engine
5. **Dead Code**: Unused code detection
6. **CLI**: Production-ready command-line interface
7. **Testing**: Comprehensive test suite
8. **Documentation**: User guide, API docs, examples

---

## Phase 1: Core Completion (8-12h) - CRITICAL

### 1.1 Complete Parser (3-4h) ✅ COMPLETE
**Priority: CRITICAL** - Nothing works without a complete parser

- [x] **Expression parsing completion**
  - Match expressions (PHP 8.0) ✓
  - Null coalescing assignment (??=) ✓
  - Spread operator in arrays ✓
  - Arrow functions with attributes ✓
  - Ternary and elvis operators ✓
  - Method calls and property access (including nullsafe) ✓

- [x] **Statement parsing completion**
  - Try/catch with multiple exception types ✓
  - Switch/match comprehensive coverage ✓
  - Declare directives (ticks, encoding) ✓
  - Global, static, unset statements ✓

- [x] **Modern PHP 8.x features**
  - Readonly classes (PHP 8.2) ✓
  - DNF types (PHP 8.2) - `(A&B)|(C&D)` ✓
  - Constants in traits ✓
  - Attributes on all declarations ✓
  - Interface and enum parsing ✓
  - Constructor property promotion ✓

- [ ] **Robustness** (deferred to Phase 5)
  - Better error recovery (don't fail on single parse error)
  - Preserve whitespace/comments as metadata (for code generation)
  - Line/column tracking for all nodes (partially done)

### 1.2 Complete Emit - Code Generation (3-4h) ✅ COMPLETE
**Priority: CRITICAL** - Required for all transformations

- [x] **Pretty printer from AST**
  - Generate readable PHP code ✓
  - All statements (match, try/catch, declare, global, static, unset) ✓
  - All expressions (closures, arrow functions, yield, throw) ✓
  - All declarations (interface, trait, enum, functions, classes) ✓
  - Attributes on all declarations ✓
  - DNF types with proper parenthesization ✓
  - Constructor property promotion ✓

- [ ] **Transformation output** (deferred to Phase 4)
  - Apply transform passes to AST
  - Emit modified code
  - Diff generation (show what changed)

- [ ] **Code style enforcement** (deferred to Phase 4)
  - PSR-12 compliance option
  - WordPress coding standards option
  - Configurable brace style, spacing

### 1.3 Type Inference Completion (2-3h)
**Priority: HIGH** - Enables automatic type hint addition

- [ ] **Basic type inference**
  - Infer return types from function bodies
  - Infer parameter types from usage
  - Propagate types through assignments

- [ ] **WordPress type inference**
  - Recognize WordPress function signatures
  - Hook parameter type inference
  - WP_Query, WP_Post type awareness

- [ ] **Generics awareness**
  - array<T> inference
  - Collection type tracking

---

## Phase 2: Advanced Analysis (8-10h)

### 2.1 Complete Taint Tracking (3-4h)
**Priority: HIGH** - Critical for security analysis accuracy

- [ ] **Data flow graph**
  - Build control flow graph
  - Track tainted data propagation
  - Source → Sink analysis

- [ ] **Taint sources**
  - Superglobals ($_GET, $_POST, $_COOKIE, etc.)
  - Database query results (trust context)
  - User input functions (file_get_contents, etc.)

- [ ] **Sanitizers recognition**
  - WordPress sanitization functions
  - PHP filter functions
  - Custom sanitizer patterns

- [ ] **Sinks**
  - SQL queries, shell commands
  - File operations, eval
  - Output (echo, print)

### 2.2 WordPress-Specific Deep Analysis (2-3h)
**Priority: MEDIUM** - Differentiator for WP developers

- [ ] **Hook analysis**
  - Detect priority conflicts
  - Find missing/misplaced hooks
  - Identify wrong hook usage

- [ ] **Capability checking**
  - Find missing current_user_can() checks
  - Detect privilege escalation risks
  - Admin vs frontend context

- [ ] **Nonce verification**
  - Comprehensive CSRF detection
  - Find form submissions without nonces
  - AJAX handler nonce checking

- [ ] **Database query analysis**
  - $wpdb->prepare() compliance
  - Direct SQL detection
  - Table prefix usage

- [ ] **Internationalization**
  - Find untranslated strings
  - Detect missing text domains
  - Check escaping+translation combos

### 2.3 Advanced Security Checks (3-4h)
**Priority: HIGH** - Beyond basic OWASP

- [ ] **Time-of-check-time-of-use (TOCTOU)**
  - File operation race conditions
  - Permission check bypasses

- [ ] **Regular expression DoS (ReDoS)**
  - Detect catastrophic backtracking patterns
  - Flag unsafe regex in preg_* functions

- [ ] **Server-Side Request Forgery (SSRF)**
  - wp_remote_get/post with user input
  - file_get_contents with URLs

- [ ] **XML External Entity (XXE)**
  - simplexml_load_* without disable_entity_loader
  - DOMDocument loadXML safety

- [ ] **Insecure direct object references**
  - Missing ownership checks on database queries
  - User ID manipulation detection

- [ ] **Mass assignment vulnerabilities**
  - Unvalidated array assignments to models

---

## Phase 3: Production CLI & Tooling (6-8h)

### 3.1 Enhanced CLI (3-4h) ✅ COMPLETE
**Priority: HIGH** - User-facing interface

- [x] **Command improvements**
  - `sanctify analyze` - full analysis with report ✓
  - `sanctify fix --interactive` - interactive fixing with previews ✓
  - `sanctify fix --diff` - show unified diff of changes ✓
  - `sanctify --watch` - watch mode for development ✓

- [x] **Output formats**
  - JSON (machine-readable) ✓
  - SARIF (GitHub/GitLab integration) ✓
  - HTML (rich visualization) ✓
  - Terminal (text output) ✓

- [x] **Filtering & targeting**
  - `--severity=high,critical` - filter by severity ✓
  - `--type=sql,xss` - filter by vulnerability type ✓
  - `--in-place` - apply fixes to files ✓
  - `--verbose` - detailed output ✓

- [ ] **Performance** (deferred to Phase 6)
  - Parallel file processing
  - Incremental analysis (only changed files)
  - Result caching
  - `.sanctifyignore` support

### 3.2 Integration & Export (2-3h)
**Priority: MEDIUM** - DevOps integration

- [ ] **CI/CD integration**
  - Exit codes for CI failure
  - GitHub Actions integration
  - GitLab CI templates
  - Pre-commit hooks

- [ ] **IDE integration preparation**
  - Language Server Protocol (LSP) foundations
  - JSON-RPC interface
  - Real-time analysis hooks

- [ ] **Configuration export**
  - php.ini hardening recommendations
  - nginx/Apache security headers
  - Guix/Nix package definitions
  - Docker security options

### 3.3 Reporting & Metrics (1-2h)
**Priority: MEDIUM** - Visibility and tracking

- [ ] **Comprehensive reports**
  - Executive summary
  - Trend analysis (compare with previous scans)
  - Remediation guidance with code examples
  - Risk scoring

- [ ] **Metrics & dashboards**
  - Security score calculation
  - Issue distribution (by type, severity, file)
  - Fix effort estimation
  - Progress tracking

---

## Phase 4: Advanced Transformations (6-8h)

### 4.1 Automatic Fixes (4-5h)
**Priority: HIGH** - Save developer time

- [ ] **Safe auto-fixes** (zero-risk, always apply)
  - Add `declare(strict_types=1)`
  - Add ABSPATH check to WP files
  - Convert `rand()` → `random_int()`
  - Add `exit` after `wp_redirect()`
  - Fix missing text domains in i18n functions

- [ ] **Semi-automatic fixes** (suggest with preview)
  - Wrap superglobals with sanitizers
  - Replace `$wpdb->query()` with `$wpdb->prepare()`
  - Add nonce verification scaffolding
  - Wrap `echo` with `esc_html()`

- [ ] **Type hint addition**
  - Infer and add parameter types
  - Infer and add return types
  - Add property types

- [ ] **Modernization**
  - Convert old array() → []
  - Convert isset() chains → null coalescing
  - Convert create_function() → closures

### 4.2 Code Quality Transformations (2-3h)
**Priority: MEDIUM** - Beyond security

- [ ] **PSR compliance**
  - Naming conventions
  - File organization
  - Docblock generation

- [ ] **WordPress standards**
  - Yoda conditions
  - Brace style
  - Hook documentation

---

## Phase 5: Testing & Documentation (4-6h)

### 5.1 Test Suite (2-3h)
**Priority: HIGH** - Ensure reliability

- [ ] **Unit tests**
  - Parser tests (golden files)
  - Analysis tests (vulnerability detection)
  - Transform tests (before/after)

- [ ] **Integration tests**
  - Full WordPress plugin analysis
  - Real-world vulnerability detection
  - Fix application verification

- [ ] **Property-based testing**
  - Parser round-trip (parse → emit → parse)
  - Transform idempotence

### 5.2 Documentation (2-3h)
**Priority: MEDIUM** - User success

- [ ] **User guide**
  - Installation (Cabal, Stack, Nix, binaries)
  - Quick start tutorial
  - Configuration guide
  - Workflow examples

- [ ] **Rule documentation**
  - Security check reference
  - Transform catalog
  - WordPress-specific rules

- [ ] **API documentation**
  - Haddock coverage
  - Library usage examples
  - Extension guide

---

## Phase 6: Advanced Features (Optional, 4-6h)

### 6.1 Machine Learning Integration (2-3h)
**Priority: LOW** - Cutting edge, experimental

- [ ] **Pattern learning**
  - Learn safe patterns from codebase
  - Reduce false positives
  - Suggest fixes based on codebase style

- [ ] **Anomaly detection**
  - Find unusual code patterns
  - Detect obfuscated malware

### 6.2 Plugin Ecosystem (2-3h)
**Priority: LOW** - Extensibility

- [ ] **Custom rule engine**
  - DSL for defining custom checks
  - Custom transformation passes
  - Project-specific rules

- [ ] **Plugin architecture**
  - Load external analysis modules
  - Custom sanitizer definitions
  - Framework-specific analyzers (Laravel, Symfony, etc.)

---

## Summary: Path to 100%

| Phase | Hours | Completion Gain | Target % |
|-------|-------|-----------------|----------|
| Current | - | - | 40% |
| Phase 1: Core Completion | 8-12 | +25% | 65% |
| Phase 2: Advanced Analysis | 8-10 | +15% | 80% |
| Phase 3: Production CLI | 6-8 | +10% | 90% |
| Phase 4: Advanced Transforms | 6-8 | +5% | 95% |
| Phase 5: Testing & Docs | 4-6 | +5% | 100% |
| **TOTAL** | **32-44h** | **+60%** | **100%** |

**Critical Path (to 80%):**
1. Complete Parser (4h)
2. Complete Emit (4h)
3. Complete Type Inference (3h)
4. Complete Taint Tracking (4h)
5. WordPress Deep Analysis (3h)
6. Enhanced CLI (4h)
7. Automatic Fixes (5h)

**Total Critical Path: 27h**
