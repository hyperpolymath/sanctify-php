# Sanctify-PHP Test Suite

Comprehensive test suite for validating parser, security analysis, and transformation functionality.

## Test Modules

### ParserSpec.hs
Tests for the PHP 8.2+ parser:
- **Modern PHP Features**: readonly classes, DNF types, enums, attributes
- **Expression Parsing**: match expressions, arrow functions, null coalescing assignment
- **Statement Parsing**: traits, interfaces, constructor promotion
- **Round-trip Testing**: parse → emit → parse validation
- **Error Recovery**: syntax error handling and reporting

### SecuritySpec.hs
Tests for vulnerability detection:
- **SQL Injection**: Direct queries, WordPress $wpdb usage, prepared statements
- **XSS Detection**: Unsanitized output, proper escaping validation
- **Command Injection**: shell_exec, exec, system with user input
- **Advanced Threats**: ReDoS patterns, SSRF, XXE vulnerabilities
- **WordPress Security**: Nonce verification, capability checks, AJAX security

### TransformSpec.hs
Tests for code transformations:
- **Strict Types**: declare(strict_types=1) addition
- **Output Escaping**: esc_html, esc_attr wrapping
- **Input Sanitization**: sanitize_text_field, sanitize_email
- **SQL Preparation**: $wpdb->prepare wrapping
- **Redirect Safety**: exit after wp_redirect
- **Type Hints**: Automatic type inference and addition
- **Crypto Modernization**: rand() → random_int(), md5() → SHAKE3-256
- **Idempotence**: Transformations don't double-apply

## Test Fixtures

Located in `test/fixtures/`:

- **vulnerable-sql.php**: SQL injection examples (unsafe concatenation)
- **vulnerable-xss.php**: XSS vulnerabilities (unsanitized output)
- **wordpress-unsafe.php**: WordPress security issues (missing nonces, capabilities)
- **wordpress-safe.php**: Properly secured WordPress code (correct patterns)
- **php82-features.php**: PHP 8.2+ syntax examples (for parser testing)

## Running Tests

### Run all tests
```bash
cabal test
```

### Run with verbose output
```bash
cabal test --test-show-details=direct
```

### Run specific test module
```bash
cabal test --test-options="--match ParserSpec"
cabal test --test-options="--match SecuritySpec"
cabal test --test-options="--match TransformSpec"
```

### Run specific test case
```bash
cabal test --test-options="--match 'parses readonly classes'"
```

### Run tests in watch mode (re-run on file changes)
```bash
ghcid --test="main"
```

## Test Coverage Goals

- **Parser**: 100% coverage of PHP 8.2+ syntax
- **Security Analysis**: All OWASP Top 10 vulnerabilities
- **WordPress Checks**: All WordPress-specific security patterns
- **Transformations**: All safe and semi-automatic fixes
- **Edge Cases**: Error recovery, malformed input, boundary conditions

## Adding New Tests

1. Add test case to appropriate Spec file (ParserSpec, SecuritySpec, TransformSpec)
2. Create fixture file in `test/fixtures/` if needed
3. Run tests to validate: `cabal test`
4. Ensure test follows existing patterns (describe/it structure)

## Test Framework

- **Hspec**: BDD-style testing framework
- **hspec-discover**: Automatic test discovery
- **hspec-golden**: Golden file testing for parser
- **hspec-megaparsec**: Parser-specific assertions

## Continuous Integration

Tests run automatically on:
- Every commit (GitHub Actions)
- Pull requests (required to pass)
- Release builds (blocking)

## Test Output Formats

- **Terminal**: Colorized test results with pass/fail indicators
- **JSON**: Machine-readable test results for CI integration
- **HTML**: Rich test reports with coverage metrics
