# Target Audience & Use Cases

This document clarifies when to use sanctify-php and php-aegis based on real-world integration feedback.

---

## Quick Decision Matrix

### Should I use sanctify-php?

| Your Situation | Use sanctify-php? | Why |
|----------------|------------------|-----|
| New PHP project | ✅ Yes | Catch issues early |
| Legacy codebase audit | ✅ Yes | Find security debt |
| WordPress plugin/theme | ⚠️ Maybe | WP already has security APIs |
| CI/CD security gate | ✅ Yes (when binaries exist) | Automated scanning |
| **GHC not installed** | ❌ **No** | Tool cannot run |

### Should I use php-aegis?

| Your Situation | Use php-aegis? | Why |
|----------------|---------------|-----|
| WordPress plugin/theme | ⚠️ **Only for unique features** | WP core has equivalent security |
| Laravel/Symfony app | ✅ Yes | Complements framework security |
| Vanilla PHP app | ✅ Yes | Provides missing security layer |
| Semantic web (RDF/Turtle) | ✅ **Yes - unique value** | No other library handles this |
| IndieWeb (Micropub, etc.) | ✅ **Yes - unique value** | Protocol-specific security |
| ActivityPub/Fediverse | ✅ **Yes - unique value** | Content policy enforcement |

---

## sanctify-php: When to Use

### Ideal Use Cases

1. **Security Audits**
   - Scanning legacy codebases for vulnerabilities
   - Pre-deployment security checks
   - Compliance requirements (PCI, SOC2)

2. **CI/CD Integration**
   - Block PRs with security issues
   - Generate SARIF reports for GitHub Security
   - Track security debt over time

3. **Code Transformation**
   - Auto-add `declare(strict_types=1)`
   - Insert missing escaping functions
   - Enforce WordPress coding standards

### When NOT to Use

1. **GHC Not Available** (BLOCKER)
   - sanctify-php requires Haskell compiler
   - Until pre-built binaries exist, many environments can't use it
   - Workaround: Docker container (when available)

2. **Already Well-Secured WordPress Plugins**
   - Mature plugins like Zotpress already follow WP security best practices
   - sanctify-php adds limited value if codebase is already clean
   - May still be useful for regression detection

3. **Quick One-Off Scripts**
   - Overhead not worth it for disposable code
   - Use php-aegis runtime protection instead

---

## php-aegis: When to Use

### Ideal Use Cases

1. **Non-WordPress PHP Applications**
   ```php
   // Laravel, Symfony, vanilla PHP
   use Aegis\Escape;
   echo Escape::html($userInput);
   ```

2. **Semantic Web Applications** (UNIQUE VALUE)
   ```php
   // RDF/Turtle output - WordPress can't do this
   use Aegis\Semantic\Turtle;
   echo '"' . Turtle::escapeString($label) . '"';
   ```

3. **IndieWeb Applications** (UNIQUE VALUE)
   ```php
   // Micropub content sanitization
   use Aegis\IndieWeb\Micropub;
   $safe = Micropub::sanitizeContent($content, ['allow_html' => true]);
   ```

4. **ActivityPub/Fediverse** (UNIQUE VALUE)
   ```php
   // Federated content policies
   use Aegis\ActivityPub\Content;
   $safe = Content::sanitize($post, ContentPolicy::STRICT);
   ```

### When NOT to Use

1. **WordPress Plugins/Themes (for standard security)**

   WordPress already provides:
   | Need | WordPress Function | php-aegis Adds Nothing |
   |------|-------------------|----------------------|
   | HTML escape | `esc_html()` | ❌ |
   | Attribute escape | `esc_attr()` | ❌ |
   | URL escape | `esc_url()` | ❌ |
   | JS escape | `esc_js()` | ❌ |
   | Email validation | `is_email()` | ❌ |
   | Sanitize text | `sanitize_text_field()` | ❌ |

   **Exception**: Use php-aegis for Turtle/RDF/IndieWeb in WordPress themes.

2. **PHP 7.4 Environments (until compat package exists)**
   - php-aegis requires PHP 8.1+
   - WordPress supports PHP 7.4+
   - Need `php-aegis-compat` package first

---

## Combined Use: When Both Tools Add Value

The tools complement each other best when:

### Scenario: Semantic WordPress Theme

```
┌─────────────────────────────────────────────────────────────┐
│ WordPress theme with RDF/Turtle output (IndieWeb/Semantic) │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  sanctify-php:                                               │
│    • Detects Turtle output context                          │
│    • Warns: "esc_html() wrong for Turtle, use Aegis"        │
│    • Auto-inserts: Aegis\Semantic\Turtle::escapeString()    │
│                                                              │
│  php-aegis:                                                  │
│    • Provides runtime Turtle escaping                        │
│    • W3C-compliant string/IRI handling                       │
│    • WordPress doesn't have this capability                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Scenario: Laravel API with Security Requirements

```
┌─────────────────────────────────────────────────────────────┐
│ Laravel API with strict security requirements               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  sanctify-php (CI/CD):                                       │
│    • SARIF reports in GitHub Security                        │
│    • Block PRs with SQL injection                            │
│    • Enforce type hints on all functions                     │
│                                                              │
│  php-aegis (runtime):                                        │
│    • Defense in depth for validation                         │
│    • Consistent escaping API                                 │
│    • Additional validators (IP, UUID, credit card)           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Scenario: Standard WordPress Plugin

```
┌─────────────────────────────────────────────────────────────┐
│ Standard WordPress plugin (no semantic web)                 │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  sanctify-php: ⚠️ Limited value                             │
│    • May catch issues WP doesn't                             │
│    • Useful for security audit                               │
│    • But WP security is already comprehensive                │
│                                                              │
│  php-aegis: ❌ No value                                      │
│    • WordPress already has esc_html(), etc.                  │
│    • Adding Aegis duplicates existing functions              │
│    • Exception: Use for unique validators WP lacks           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Summary: Unique Value Propositions

### sanctify-php Unique Value

| Capability | Competition | sanctify-php Advantage |
|------------|-------------|----------------------|
| PHP static analysis | PHPStan, Psalm | Security-focused, not just types |
| WordPress awareness | PHPCS-WPCS | Deeper taint tracking |
| Auto-fix transforms | None | Automatic code hardening |
| SARIF output | Few tools | GitHub Security integration |
| Semantic context | None | Detects Turtle/JSON-LD contexts |

### php-aegis Unique Value

| Capability | Competition | php-aegis Advantage |
|------------|-------------|---------------------|
| Turtle/RDF escaping | **None** | Only library for semantic web |
| Micropub sanitization | **None** | IndieWeb protocol security |
| ActivityPub content | **None** | Fediverse content policies |
| Context-aware escaping | Laravel, WP | Unified API across frameworks |
| UUID/IP/credit card | Various | Consolidated validation library |

---

## Recommendations

### For php-aegis Team

1. **Don't compete with WordPress core** — document that php-aegis is for non-WP apps or unique WP needs
2. **Focus on unique value** — Turtle, IndieWeb, ActivityPub are unserved markets
3. **Create framework adapters** — Laravel, Symfony, WordPress (for unique features only)

### For sanctify-php Team

1. **Pre-built binaries are MANDATORY** — tool literally cannot be used without them
2. **Docker image as fallback** — for environments that can't install binaries
3. **Document when NOT to use** — mature WP plugins may not benefit

---

*SPDX-License-Identifier: PMPL-1.0-or-later
*SPDX-FileCopyrightText: 2024-2025 hyperpolymath*
