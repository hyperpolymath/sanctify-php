# Standalone vs Combined Capabilities

This document defines what each tool must provide independently and the enhanced capabilities when used together.

---

## Philosophy

Each tool should be **fully functional standalone**. Integration provides **enhanced capabilities**, not basic functionality.

```
┌─────────────────────────────────────────────────────────────────┐
│                      Standalone Operation                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   sanctify-php (alone)         php-aegis (alone)                │
│   ┌─────────────────┐         ┌─────────────────┐              │
│   │ Static Analysis │         │ Runtime Library │              │
│   │ Auto-transform  │         │ Escaping/Sanit. │              │
│   │ Uses WP funcs   │         │ Works anywhere  │              │
│   └─────────────────┘         └─────────────────┘              │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                      Combined Operation                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────────────────────────────────────────┐          │
│   │              sanctify-php + php-aegis            │          │
│   │                                                  │          │
│   │  • sanctify detects → inserts php-aegis calls   │          │
│   │  • php-aegis provides runtime protection        │          │
│   │  • Semantic escaping (Turtle, JSON-LD)          │          │
│   │  • IndieWeb protocol security                   │          │
│   │  • Deeper taint analysis with Aegis sinks       │          │
│   └─────────────────────────────────────────────────┘          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## sanctify-php: Minimum Viable Standalone

### Must Have (MVP)

| Capability | Status | Notes |
|------------|--------|-------|
| Detect missing `strict_types` | ✅ | Core feature |
| Detect SQL injection | ✅ | Taint tracking |
| Detect XSS vulnerabilities | ✅ | Output escaping |
| Detect CSRF missing nonces | ✅ | WordPress-aware |
| Auto-add `strict_types` | ✅ | Transform |
| Auto-add WordPress escaping | ✅ | Uses `esc_html()` etc. |
| SARIF output for CI | ✅ | GitHub integration |
| **Pre-built binaries** | ❌ → Priority | Adoption blocker |
| **Composer install** | ❌ → Priority | Adoption blocker |

### Standalone Behavior (Without php-aegis)

When php-aegis is not installed, sanctify-php must:

1. **Use WordPress functions for escaping**:
   ```php
   // sanctify-php auto-fix output (standalone)
   echo esc_html($user_input);  // NOT Aegis\Escape::html()
   ```

2. **Use WordPress functions for sanitization**:
   ```php
   // sanctify-php auto-fix output (standalone)
   $clean = sanitize_text_field($_POST['field']);
   ```

3. **Warn about missing semantic escaping**:
   ```
   WARNING: Turtle output detected at semantic.php:45
   No semantic escaping library found.
   Consider installing php-aegis for proper Turtle escaping.
   Using esc_html() as fallback (may break RDF syntax).
   ```

### Installation Requirements (Standalone)

```bash
# MUST work without Haskell
composer require --dev hyperpolymath/sanctify-php

# Binary auto-downloads on install
# No manual steps required
```

---

## php-aegis: Minimum Viable Standalone

### Must Have (MVP)

| Capability | Status | Notes |
|------------|--------|-------|
| HTML escaping | ✅ | `Escape::html()` |
| Attribute escaping | ✅ | `Escape::attr()` |
| URL validation | ✅ | `Validate::url()` |
| Email validation | ✅ | `Validate::email()` |
| **PHP 7.4+ compatibility** | ❌ → Critical | Adoption blocker |
| **WordPress adapter** | ❌ → Priority | snake_case functions |
| **Int/IP/Domain validators** | ❌ → Priority | Common needs |
| **Turtle escaping** | ❌ → Priority | Unique value |

### Standalone Behavior (Without sanctify-php)

When sanctify-php is not used, php-aegis must:

1. **Work with any PHP framework**:
   ```php
   // Generic PHP usage
   use Aegis\Escape;
   echo Escape::html($userInput);
   ```

2. **Provide WordPress helpers**:
   ```php
   // WordPress plugin/theme usage
   require_once 'vendor/autoload.php';
   // Functions auto-registered if ABSPATH defined
   echo aegis_escape_html($userInput);
   ```

3. **Not require static analysis**:
   - Library is purely runtime
   - Developer chooses where to use escaping
   - No build step needed

### Installation Requirements (Standalone)

```bash
# MUST work on PHP 7.4+
composer require hyperpolymath/php-aegis-compat  # PHP 7.4-8.0
# OR
composer require hyperpolymath/php-aegis         # PHP 8.1+
```

---

## Combined Capabilities

When both tools are used together, additional capabilities unlock:

### 1. Aegis-Aware Auto-Fix

sanctify-php inserts php-aegis calls instead of WordPress functions:

```php
// Before
echo $user_input;

// After (with php-aegis)
echo \Aegis\Escape::html($user_input);

// After (without php-aegis)
echo esc_html($user_input);
```

### 2. Semantic Context Detection

sanctify-php detects Turtle/JSON-LD output and suggests correct Aegis escaping:

```php
// sanctify-php detects Turtle context
header('Content-Type: text/turtle');
echo "<{$subject}> <{$predicate}> \"{$object}\" .";

// Recommends:
echo "<" . \Aegis\Semantic\Turtle::escapeIRI($subject) . "> "
   . "<" . \Aegis\Semantic\Turtle::escapeIRI($predicate) . "> "
   . "\"" . \Aegis\Semantic\Turtle::escapeString($object) . "\" .";
```

### 3. Deep Taint Analysis

sanctify-php recognizes Aegis sanitizers as safe sinks:

```php
// sanctify-php knows this is safe
$content = \Aegis\IndieWeb\Micropub::sanitizeContent($_POST['content']);
echo $content;  // No warning - recognized as sanitized
```

### 4. Configuration Alignment

Both tools share configuration:

```json
// sanctify.json
{
  "runtime_library": "php-aegis",
  "semantic_contexts": ["turtle", "jsonld"],
  "transforms": {
    "use_aegis": true,
    "fallback": "wordpress"
  }
}
```

---

## Feature Matrix

| Feature | sanctify-php alone | php-aegis alone | Combined |
|---------|-------------------|-----------------|----------|
| Detect XSS | ✅ | ❌ | ✅ |
| Fix XSS | ✅ (WP funcs) | ❌ | ✅ (Aegis) |
| Runtime escaping | ❌ | ✅ | ✅ |
| Turtle escaping | ⚠️ Warning only | ✅ | ✅ Auto-insert |
| JSON-LD escaping | ⚠️ Warning only | ✅ | ✅ Auto-insert |
| IndieWeb sanitization | ⚠️ Warning only | ✅ | ✅ Auto-insert |
| Taint tracking | ✅ | ❌ | ✅ Enhanced |
| CI/CD integration | ✅ SARIF | ❌ | ✅ SARIF |
| WordPress integration | ✅ | ✅ | ✅ Seamless |
| PHP 7.4 support | ✅ (binary) | ⚠️ (compat pkg) | ✅ |

---

## Adoption Path

### Path A: Start with sanctify-php (Static Analysis First)

```bash
# 1. Install and run analysis
composer require --dev hyperpolymath/sanctify-php
vendor/bin/sanctify-php analyze src/

# 2. Apply auto-fixes (uses WordPress functions)
vendor/bin/sanctify-php fix src/

# 3. Later: Add php-aegis for semantic escaping
composer require hyperpolymath/php-aegis

# 4. Re-run sanctify to upgrade to Aegis calls
vendor/bin/sanctify-php fix src/ --use-aegis
```

### Path B: Start with php-aegis (Runtime Library First)

```bash
# 1. Install runtime library
composer require hyperpolymath/php-aegis

# 2. Manually add escaping where needed
# Use Aegis\Escape::html(), Aegis\Semantic\Turtle::escapeString(), etc.

# 3. Later: Add sanctify-php for automated detection
composer require --dev hyperpolymath/sanctify-php

# 4. Find missed spots
vendor/bin/sanctify-php analyze src/
```

### Path C: Install Both (Recommended)

```bash
# Install both together
composer require hyperpolymath/php-aegis
composer require --dev hyperpolymath/sanctify-php

# Analyze and fix in one step
vendor/bin/sanctify-php fix src/ --use-aegis
```

---

## Minimum Implementation Checklist

### sanctify-php v0.2.0 (Standalone-Ready)

- [ ] Pre-built binaries (linux-x86_64, darwin-x86_64, darwin-arm64)
- [ ] Composer plugin that auto-downloads binary
- [ ] GitHub Action
- [ ] Standalone mode: use WordPress functions when Aegis not found
- [ ] Warning mode: alert when semantic escaping needed but Aegis missing

### php-aegis v0.2.0 (Standalone-Ready)

- [ ] php-aegis-compat package (PHP 7.4+)
- [ ] WordPress adapter (snake_case functions)
- [ ] Extended validators: `int()`, `ip()`, `domain()`, `uuid()`, `slug()`
- [ ] Turtle escaping: `Semantic\Turtle::escapeString()`, `escapeIRI()`
- [ ] Works without sanctify-php or any build step

---

*SPDX-License-Identifier: MIT OR AGPL-3.0-or-later*
*SPDX-FileCopyrightText: 2024-2025 hyperpolymath*
