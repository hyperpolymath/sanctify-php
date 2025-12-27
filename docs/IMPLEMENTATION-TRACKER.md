# Implementation Tracker

## Status Overview

| Area | Status | Next Action |
|------|--------|-------------|
| php-aegis Handover | ✅ Complete | Send to php-aegis team |
| sanctify-php Roadmap | ✅ Complete | Begin Phase 1 |
| Standalone Requirements | ✅ Complete | See STANDALONE.md |
| Target Audience | ✅ Complete | See TARGET-AUDIENCE.md |
| Upstream Issues | ✅ Complete | See UPSTREAM-ISSUES.md |
| Binary Releases | 🔲 Not Started | **BLOCKER** - Tool cannot run without this |
| Composer Plugin | 🔲 Not Started | **CRITICAL** - Enable `composer require` |
| Docker Container | 🔲 Not Started | **HIGH** - Fallback for binary issues |
| GitHub Action | 🔲 Not Started | High priority |
| Incremental Analysis | 🔲 Not Started | Cache for performance |
| Semantic Support | 🔲 Not Started | Design AST extensions |

---

## Critical Finding: GHC Requirement is a BLOCKER

### Integration Evidence

| Project | Could run sanctify-php? | php-aegis Value? | Result |
|---------|------------------------|------------------|--------|
| wp-sinople-theme | ⚠️ With difficulty | ⚠️ Limited | Needed Haskell setup |
| Zotpress | ❌ **NO** | ❌ None | GHC not available |
| sinople-theme | ✅ **CI Integration** | ✅ **Turtle!** | Success with unique value focus |
| Sinople (full) | ✅ **Real vuln found** | ✅ **Critical fix** | TurtleEscaper fixed RDF injection |

> **Zotpress integration failed completely** — sanctify-php could not be executed.
> Manual analysis was performed instead using documented patterns.
> This is not an inconvenience — it's a **total adoption blocker**.

---

## Critical Path: Adoption Blockers

> **Key Insight**: The Haskell dependency is a BLOCKER, not just an inconvenience.
> In real-world integrations, the tool literally could not be used.
> PHP developers cannot and will not install GHC.

### sanctify-php Critical Items

| Item | Priority | Blocks |
|------|----------|--------|
| Pre-built binaries | **CRITICAL** | Everything else |
| Composer plugin wrapper | **CRITICAL** | PHP dev adoption |
| GitHub Action | High | CI/CD adoption |
| Incremental analysis | Medium | Performance at scale |

### php-aegis Critical Items

| Item | Priority | Blocks |
|------|----------|--------|
| php-aegis-compat (PHP 7.4+) | **CRITICAL** | WordPress adoption |
| WordPress adapter (snake_case) | High | WP dev experience |
| Extended validators | Medium | Common use cases |

---

## Immediate Actions

### For php-aegis Team

1. **Review handover document**: `docs/PHP-AEGIS-HANDOVER.md`
2. **Critical implementation** (adoption blockers):
   - [ ] Create `php-aegis-compat` package for PHP 7.4+
   - [ ] Add WordPress adapter with snake_case functions
   - [ ] Extend `Validate` class: `int()`, `ip()`, `domain()`
3. **Priority implementation** (unique value):
   - [ ] `Aegis\Semantic\Turtle::escapeString()`
   - [ ] `Aegis\Semantic\Turtle::escapeIRI()`
   - [ ] SPDX headers on all files

### For sanctify-php Team

1. **Phase 1 CRITICAL**: Enable `composer require` installation
   - [ ] GitHub Actions for binary releases (linux, darwin x86_64/arm64)
   - [ ] Composer plugin that auto-downloads binary on install
   - [ ] GitHub Action for CI/CD integration
   - [ ] Dockerfile for container distribution

2. **Phase 1 HIGH**: Performance
   - [ ] Incremental analysis with file hash cache
   - [ ] Only rescan changed files

3. **Phase 2 Priority**: Semantic web support
   - [ ] Create `Sanctify.Analysis.Semantic` module
   - [ ] Extend taint sinks for Turtle/JSON-LD contexts
   - [ ] Add WordPress semantic theme detection

---

## Cross-Team Coordination

### Shared Namespace Agreement

Both tools should recognize these function signatures:

```php
// php-aegis provides these at runtime
Aegis\Semantic\Turtle::escapeString(string $value): string
Aegis\Semantic\Turtle::escapeIRI(string $iri): string
Aegis\Semantic\JsonLd::escapeValue(mixed $value): string
Aegis\IndieWeb\Micropub::sanitizeContent(string $content, array $context = []): string
Aegis\IndieWeb\IndieAuth::verifyToken(string $token, string $endpoint): array|false
```

```haskell
-- sanctify-php recognizes these as safe sinks
aegisSemantic :: [Text]
aegisSemantic =
  [ "Aegis\\Semantic\\Turtle::escapeString"
  , "Aegis\\Semantic\\Turtle::escapeIRI"
  , "Aegis\\Semantic\\JsonLd::escapeValue"
  , "Aegis\\IndieWeb\\Micropub::sanitizeContent"
  ]
```

### Integration Testing

When both tools are updated:

```bash
# 1. Analyze code that uses php-aegis
sanctify-php analyze ./project --aegis-aware

# 2. Verify no false positives for Aegis-escaped output
# 3. Verify Turtle context detection works
# 4. Verify auto-fix inserts correct Aegis calls
```

---

## Issue Templates

### For php-aegis Repository

**Title**: Add semantic web escaping support (RDF/Turtle)

**Body**:
```markdown
## Context
Integration feedback from wp-sinople-theme identified missing RDF/Turtle escaping functions.

## Requirements
- [ ] `Aegis\Semantic\Turtle::escapeString()` - W3C Turtle string escaping
- [ ] `Aegis\Semantic\Turtle::escapeIRI()` - IRI validation and escaping
- [ ] Follow escape rules from https://www.w3.org/TR/turtle/#sec-escapes

## Reference Implementation
See sanctify-php `docs/PHP-AEGIS-HANDOVER.md` for reference code.

## Testing
Should correctly escape:
- Backslashes, quotes, newlines, tabs
- Unicode control characters (U+0000 to U+001F)
- Invalid IRI characters per RFC 3987
```

### For sanctify-php Repository

**Title**: Add pre-built binary releases

**Body**:
```markdown
## Problem
Users need Haskell toolchain to build sanctify-php, preventing adoption.

## Solution
Provide statically-linked binaries via GitHub Releases for:
- linux-x86_64
- linux-aarch64
- darwin-x86_64
- darwin-aarch64
- windows-x86_64

## Implementation
- [ ] GitHub Actions workflow with matrix strategy
- [ ] Static linking flags
- [ ] GPG signing
- [ ] Release automation

## Reference
See `docs/ROADMAP.md` Phase 1 for details.
```

---

## Communication Channels

- **sanctify-php issues**: https://github.com/hyperpolymath/sanctify-php/issues
- **php-aegis issues**: https://github.com/hyperpolymath/php-aegis/issues

---

*SPDX-License-Identifier: MIT OR AGPL-3.0-or-later*
*SPDX-FileCopyrightText: 2024-2025 hyperpolymath*
