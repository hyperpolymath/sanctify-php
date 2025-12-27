# PHP-Aegis Handover Document

## Context

This document provides integration feedback from the wp-sinople-theme WordPress theme project, which attempted to use both `sanctify-php` (static analysis) and `php-aegis` (runtime security library) together.

**Integration Report Date**: 2025-12-27
**Integration Target**: WordPress semantic theme with IndieWeb/Micropub support

---

## Integration Feedback Summary

### Issues Identified with php-aegis

| Issue | Severity | Impact |
|-------|----------|--------|
| Feature set too minimal | Medium | WordPress has equivalent functions already |
| No RDF/Turtle escaping | High | Semantic themes require W3C-compliant escaping |
| Missing SPDX license headers | Low | Compliance concern for FOSS projects |
| No PHP 8.1+ features | Medium | Missing enums, union types, readonly properties |

---

## Detailed Recommendations

### 1. Differentiate from WordPress Core Functions

**Problem**: WordPress already provides `esc_html()`, `esc_attr()`, `sanitize_text_field()`, etc.

**Recommendation**: php-aegis should provide value *beyond* WordPress core:

```php
// INSTEAD OF duplicating WordPress functions:
Aegis\Escape::html($string);  // ← WordPress already has esc_html()

// PROVIDE specialized capabilities:
Aegis\Semantic\Turtle::escapeString($string);   // ← WordPress doesn't have this
Aegis\Semantic\Turtle::escapeIRI($iri);
Aegis\Semantic\JsonLd::sanitize($data);
Aegis\IndieWeb\Micropub::sanitizeContent($content, $context);
```

**Unique Value Opportunities**:
- Semantic web escaping (RDF, Turtle, JSON-LD, N-Triples)
- IndieWeb protocol security (Micropub, Webmention, IndieAuth)
- ActivityPub content sanitization
- Microformats security validation

### 2. Add RDF/Turtle Escaping Functions

**Problem**: Semantic WordPress themes generate RDF Turtle output. Using `addslashes()` is incorrect and allows injection.

**Required Functions**:

```php
<?php
declare(strict_types=1);
// SPDX-License-Identifier: MIT

namespace Aegis\Semantic;

final class Turtle
{
    /**
     * Escape a string for use in Turtle literals.
     * Handles: backslash, quotes, newlines, tabs, special Unicode.
     *
     * @see https://www.w3.org/TR/turtle/#sec-escapes
     */
    public static function escapeString(string $value): string
    {
        $replacements = [
            '\\' => '\\\\',
            '"'  => '\\"',
            "\n" => '\\n',
            "\r" => '\\r',
            "\t" => '\\t',
        ];

        $escaped = strtr($value, $replacements);

        // Handle control characters (U+0000 to U+001F except handled above)
        return preg_replace_callback(
            '/[\x00-\x08\x0B\x0C\x0E-\x1F]/',
            fn($m) => sprintf('\\u%04X', ord($m[0])),
            $escaped
        ) ?? $escaped;
    }

    /**
     * Validate and escape an IRI for Turtle output.
     *
     * @throws \InvalidArgumentException If IRI is malformed
     */
    public static function escapeIRI(string $iri): string
    {
        // Validate IRI structure
        if (!filter_var($iri, FILTER_VALIDATE_URL) &&
            !preg_match('/^urn:[a-z0-9][a-z0-9-]{0,31}:/i', $iri)) {
            throw new \InvalidArgumentException("Invalid IRI: {$iri}");
        }

        // Escape special characters per RFC 3987
        $escape = ['<' => '%3C', '>' => '%3E', '"' => '%22',
                   '{' => '%7B', '}' => '%7D', '|' => '%7C',
                   '\\' => '%5C', '^' => '%5E', '`' => '%60'];

        return strtr($iri, $escape);
    }
}
```

### 3. Add SPDX License Headers

**Problem**: All source files should have SPDX identifiers for license clarity.

**Standard Format**:
```php
<?php
declare(strict_types=1);
// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024-2025 hyperpolymath

namespace Aegis;
```

### 4. Adopt PHP 8.1+ Features

**Problem**: Modern PHP provides better type safety that security libraries should leverage.

**Recommendations**:

```php
<?php
declare(strict_types=1);
// SPDX-License-Identifier: MIT

namespace Aegis;

// Use enums for security contexts
enum EscapeContext: string
{
    case Html = 'html';
    case Attribute = 'attr';
    case Url = 'url';
    case Js = 'js';
    case Css = 'css';
    case Turtle = 'turtle';
    case JsonLd = 'jsonld';
}

// Use union types for flexible input
final class Escape
{
    public static function context(
        string|Stringable $value,
        EscapeContext $context
    ): string {
        return match($context) {
            EscapeContext::Html => htmlspecialchars((string)$value, ENT_QUOTES | ENT_HTML5, 'UTF-8'),
            EscapeContext::Turtle => Semantic\Turtle::escapeString((string)$value),
            // ...
        };
    }
}

// Use readonly properties for immutable security configs
final readonly class SecurityPolicy
{
    public function __construct(
        public bool $strictMode = true,
        public EscapeContext $defaultContext = EscapeContext::Html,
        public array $allowedSchemes = ['https'],
    ) {}
}
```

---

## Suggested Architecture

### Complementary Roles

| Tool | Role | When Used |
|------|------|-----------|
| **sanctify-php** | Static analysis & transformation | Build time, CI/CD |
| **php-aegis** | Runtime security library | Application runtime |

### Integration Points

```
┌─────────────────────────────────────────────────────────┐
│                    Development Flow                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│   Source Code                                            │
│       │                                                  │
│       ▼                                                  │
│   sanctify-php analyze    ◄── Static analysis           │
│       │                       Finds missing escaping    │
│       │                       Detects taint flows       │
│       │                       Reports vulnerabilities   │
│       ▼                                                  │
│   sanctify-php fix        ◄── Auto-transform            │
│       │                       Adds php-aegis calls      │
│       │                       Inserts strict_types      │
│       ▼                                                  │
│   Production Code                                        │
│       │                                                  │
│       ▼                                                  │
│   php-aegis (runtime)     ◄── Runtime protection        │
│                               Semantic escaping         │
│                               Protocol sanitization     │
│                               Defense in depth          │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Proposed php-aegis Namespace Structure

```
Aegis/
├── Escape.php                 # Core escaping (extends WP when needed)
├── Sanitize.php               # Core sanitization
├── Validate.php               # Input validation
├── Semantic/                  # ← NEW: RDF/Linked Data
│   ├── Turtle.php             # W3C Turtle escaping
│   ├── JsonLd.php             # JSON-LD sanitization
│   ├── NTriples.php           # N-Triples escaping
│   └── Rdf.php                # Generic RDF utilities
├── IndieWeb/                  # ← NEW: IndieWeb protocols
│   ├── Micropub.php           # Micropub content sanitization
│   ├── Webmention.php         # Webmention validation
│   ├── IndieAuth.php          # Token verification helpers
│   └── Microsub.php           # Microsub security
├── ActivityPub/               # ← NEW: Fediverse
│   ├── Object.php             # AS2 object sanitization
│   ├── Signature.php          # HTTP signature verification
│   └── Content.php            # HTML content policy
├── WordPress/                 # WordPress integration layer
│   ├── Hooks.php              # Security hook integration
│   └── OptionsEncryption.php  # Encrypted options storage
└── Policy/                    # Security policies
    ├── ContentSecurityPolicy.php
    └── PermissionsPolicy.php
```

---

## sanctify-php Integration Support

We will add support in sanctify-php to:

1. **Recognize php-aegis calls as safe sinks**
   ```haskell
   -- In Sanctify.Analysis.Taint
   aegisSafeSinks :: [Text]
   aegisSafeSinks =
     [ "Aegis\\Escape::html"
     , "Aegis\\Semantic\\Turtle::escapeString"
     , "Aegis\\IndieWeb\\Micropub::sanitizeContent"
     -- ...
     ]
   ```

2. **Auto-insert php-aegis calls during fix**
   ```haskell
   -- Transform unescaped output to use php-aegis
   -- Before: echo $user_input;
   -- After:  echo \Aegis\Escape::html($user_input);
   ```

3. **Detect semantic context for appropriate escaping**
   ```haskell
   -- Detect Turtle output context
   -- Recommend: \Aegis\Semantic\Turtle::escapeString()
   -- Instead of: esc_html() (wrong context)
   ```

---

## Action Items for php-aegis Team

### Priority 1 (High)
- [ ] Add `Aegis\Semantic\Turtle` namespace with W3C-compliant escaping
- [ ] Add `Aegis\IndieWeb\Micropub` for content sanitization
- [ ] Add SPDX headers to all files

### Priority 2 (Medium)
- [ ] Refactor to use PHP 8.1+ enums for contexts
- [ ] Add union types throughout API
- [ ] Document differentiation from WordPress core functions

### Priority 3 (Low)
- [ ] Add ActivityPub sanitization support
- [ ] Add JSON-LD validation
- [ ] Create WordPress integration hooks

---

## Contact

For questions about this handover or sanctify-php integration:
- Repository: hyperpolymath/sanctify-php
- Issues: https://github.com/hyperpolymath/sanctify-php/issues

---

*SPDX-License-Identifier: MIT OR AGPL-3.0-or-later*
*SPDX-FileCopyrightText: 2024-2025 hyperpolymath*
