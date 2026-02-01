# Sanctify-PHP Roadmap

## Context

This roadmap addresses integration feedback from real-world deployment:
1. **wp-sinople-theme** - Semantic theme with IndieWeb/Micropub support
2. **Zotpress** - Mature WordPress plugin (couldn't run sanctify-php at all)

**Feedback Date**: 2025-12-27
**Current Version**: 0.1.0.0

---

## Critical Finding: Tool Unusable Without Binaries

### Zotpress Integration Failure

> **sanctify-php could not be run at all** because GHC (Haskell compiler) was not available.
> Manual analysis was performed instead using documented patterns.

This confirms the #1 adoption blocker: **the Haskell build requirement prevents any usage**.

### Evidence from Integration Attempts

| Project | Could run sanctify-php? | Outcome |
|---------|------------------------|---------|
| wp-sinople-theme | ⚠️ With difficulty | Required Haskell setup |
| Zotpress | ❌ **No** | GHC not available, manual analysis only |

---

## Issues Identified

| Issue | Severity | User Impact |
|-------|----------|-------------|
| Requires Haskell toolchain | **BLOCKER** | Tool literally cannot run |
| No `composer require` install | **Critical** | PHP devs expect Composer installation |
| No pre-built binaries | **Critical** | No workaround for GHC requirement |
| No Docker container | High | Alternative deployment path missing |
| No GitHub Action | High | No easy CI/CD integration |
| No incremental analysis | Medium | Full rescan on every change is slow |
| No RDF/Turtle awareness | High | Semantic themes get false negatives |
| Limited PHP 8.x syntax | Medium | May miss some modern PHP patterns |
| Missing WP integration docs | Medium | Users don't know how to integrate |

### Key Insight

> **The Haskell dependency is a BLOCKER, not just an inconvenience.**
> In the Zotpress integration, the tool could not be used at all.
> PHP developers cannot and will not install GHC.
> **Pre-built binaries are not optional — they are required for any adoption.**

---

## Phase 1: Distribution & Accessibility

**Goal**: Make sanctify-php usable without Haskell knowledge

### 1.1 Pre-built Binaries

Provide statically-linked binaries for common platforms:

```
releases/
├── sanctify-php-0.2.0-linux-x86_64
├── sanctify-php-0.2.0-linux-aarch64
├── sanctify-php-0.2.0-darwin-x86_64
├── sanctify-php-0.2.0-darwin-aarch64
└── sanctify-php-0.2.0-windows-x86_64.exe
```

**Implementation**:
- [ ] Add GitHub Actions workflow for cross-compilation
- [ ] Use static linking (`-optl-static -optl-pthread`)
- [ ] Sign binaries (GPG + sigstore)
- [ ] Create release automation script

**CI Workflow** (`.github/workflows/release.yml`):
```yaml
name: Release Binaries
on:
  push:
    tags: ['v*']

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-linux
          - os: macos-latest
            target: x86_64-darwin
          - os: macos-latest
            target: aarch64-darwin
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: haskell-actions/setup@v2
        with:
          ghc-version: '9.6'
      - run: cabal build --enable-executable-static
      - uses: actions/upload-artifact@v4
```

### 1.2 Docker Container

Provide OCI container for easy deployment:

```dockerfile
# Dockerfile
FROM haskell:9.6-slim AS builder
WORKDIR /build
COPY . .
RUN cabal build --enable-executable-static
RUN cp $(cabal list-bin sanctify-php) /sanctify-php

FROM gcr.io/distroless/static-debian12
COPY --from=builder /sanctify-php /usr/local/bin/sanctify-php
ENTRYPOINT ["sanctify-php"]
```

**Usage**:
```bash
# Analyze a project
docker run --rm -v $(pwd):/src ghcr.io/hyperpolymath/sanctify-php analyze /src

# Generate report
docker run --rm -v $(pwd):/src ghcr.io/hyperpolymath/sanctify-php report /src --format=sarif
```

### 1.3 Composer Plugin Wrapper (Critical Path)

PHP developers expect `composer require`. Provide a Composer plugin that:
1. Detects platform (OS/arch)
2. Downloads the appropriate pre-built binary
3. Provides Composer scripts integration

**Package Structure**:
```
sanctify-php-composer/
├── composer.json
├── src/
│   ├── Plugin.php           # Composer plugin hooks
│   ├── BinaryInstaller.php  # Platform detection & download
│   └── ScriptHandler.php    # Composer scripts integration
└── bin/
    └── sanctify-php         # Wrapper script
```

**composer.json**:
```json
{
    "name": "hyperpolymath/sanctify-php",
    "description": "PHP security analysis and hardening tool",
    "type": "composer-plugin",
    "require": {
        "php": ">=7.4",
        "composer-plugin-api": "^2.0"
    },
    "require-dev": {
        "composer/composer": "^2.0"
    },
    "autoload": {
        "psr-4": { "Sanctify\\Composer\\": "src/" }
    },
    "extra": {
        "class": "Sanctify\\Composer\\Plugin",
        "sanctify-binaries": {
            "linux-x86_64": "https://github.com/hyperpolymath/sanctify-php/releases/download/v{version}/sanctify-php-linux-x86_64",
            "darwin-x86_64": "https://github.com/hyperpolymath/sanctify-php/releases/download/v{version}/sanctify-php-darwin-x86_64",
            "darwin-arm64": "https://github.com/hyperpolymath/sanctify-php/releases/download/v{version}/sanctify-php-darwin-aarch64"
        }
    },
    "scripts": {
        "sanctify:analyze": "Sanctify\\Composer\\ScriptHandler::analyze",
        "sanctify:fix": "Sanctify\\Composer\\ScriptHandler::fix",
        "sanctify:report": "Sanctify\\Composer\\ScriptHandler::report"
    },
    "bin": ["bin/sanctify-php"]
}
```

**BinaryInstaller.php**:
```php
<?php
declare(strict_types=1);
// SPDX-License-Identifier: PMPL-1.0-or-later

namespace Sanctify\Composer;

use Composer\Composer;
use Composer\IO\IOInterface;

final class BinaryInstaller
{
    private const BINARY_DIR = 'vendor/bin';

    public static function install(Composer $composer, IOInterface $io): void
    {
        $platform = self::detectPlatform();
        $version = self::getVersion($composer);
        $url = self::getBinaryUrl($composer, $platform, $version);

        $io->write("<info>Downloading sanctify-php for {$platform}...</info>");

        $binPath = self::BINARY_DIR . '/sanctify-php-bin';
        self::download($url, $binPath);
        chmod($binPath, 0755);

        $io->write("<info>sanctify-php installed successfully.</info>");
    }

    private static function detectPlatform(): string
    {
        $os = PHP_OS_FAMILY === 'Darwin' ? 'darwin' : 'linux';
        $arch = php_uname('m') === 'arm64' ? 'arm64' : 'x86_64';
        return "{$os}-{$arch}";
    }

    private static function download(string $url, string $dest): void
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $binary = curl_exec($ch);
        curl_close($ch);
        file_put_contents($dest, $binary);
    }
}
```

**Usage after installation**:
```bash
# Install
composer require --dev hyperpolymath/sanctify-php

# Use via Composer scripts
composer sanctify:analyze src/
composer sanctify:fix src/ -- --policy=conservative
composer sanctify:report src/ -- --format=sarif

# Or directly
vendor/bin/sanctify-php analyze src/
```

### 1.4 GitHub Action

Official GitHub Action for CI/CD:

```yaml
# .github/actions/sanctify-php/action.yml
name: 'Sanctify PHP'
description: 'PHP security analysis and hardening'
branding:
  icon: 'shield'
  color: 'green'

inputs:
  path:
    description: 'Path to analyze'
    required: true
    default: 'src'
  format:
    description: 'Output format (text, json, sarif, html, markdown)'
    required: false
    default: 'sarif'
  fail-on:
    description: 'Fail on severity level (critical, high, medium, low, none)'
    required: false
    default: 'high'
  upload-sarif:
    description: 'Upload SARIF to GitHub Security tab'
    required: false
    default: 'true'

outputs:
  issues-found:
    description: 'Number of security issues found'
    value: ${{ steps.analyze.outputs.issues }}

runs:
  using: 'composite'
  steps:
    - name: Download sanctify-php
      shell: bash
      run: |
        curl -LO https://github.com/hyperpolymath/sanctify-php/releases/latest/download/sanctify-php-linux-x86_64
        chmod +x sanctify-php-linux-x86_64
        sudo mv sanctify-php-linux-x86_64 /usr/local/bin/sanctify-php

    - name: Run analysis
      id: analyze
      shell: bash
      run: |
        sanctify-php analyze ${{ inputs.path }} \
          --format=${{ inputs.format }} \
          --output=sanctify-results.${{ inputs.format }} \
          --fail-on=${{ inputs.fail-on }}
        echo "issues=$(sanctify-php analyze ${{ inputs.path }} --format=json | jq '.issues | length')" >> $GITHUB_OUTPUT

    - name: Upload SARIF
      if: inputs.upload-sarif == 'true' && inputs.format == 'sarif'
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: sanctify-results.sarif
```

**Usage in workflows**:
```yaml
name: Security
on: [push, pull_request]

jobs:
  sanctify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hyperpolymath/sanctify-php-action@v1
        with:
          path: src/
          fail-on: high
```

### 1.5 Incremental Analysis

Cache analysis results and only rescan changed files:

```haskell
-- src/Sanctify/Cache.hs
-- SPDX-License-Identifier: AGPL-3.0-or-later

module Sanctify.Cache
  ( AnalysisCache(..)
  , loadCache
  , saveCache
  , getChangedFiles
  ) where

import qualified Data.Map.Strict as Map
import Crypto.Hash (SHA256, hash)

data AnalysisCache = AnalysisCache
  { cacheVersion :: Text
  , fileHashes :: Map FilePath Text  -- path -> SHA256
  , cachedResults :: Map FilePath [SecurityIssue]
  }
  deriving (Generic, FromJSON, ToJSON)

-- Determine which files need re-analysis
getChangedFiles :: AnalysisCache -> [FilePath] -> IO [FilePath]
getChangedFiles cache files = do
  filterM (hasChanged cache) files
  where
    hasChanged c f = do
      currentHash <- hashFile f
      pure $ Map.lookup f (fileHashes c) /= Just currentHash
```

**CLI usage**:
```bash
# First run: full analysis, creates .sanctify-cache.json
sanctify-php analyze src/

# Subsequent runs: only analyze changed files
sanctify-php analyze src/ --incremental

# Force full rescan
sanctify-php analyze src/ --no-cache
```

### 1.6 Guix Package

Proper Guix package definition for reproducible builds:

```scheme
;; guix.scm - enhanced for distribution
(define-public sanctify-php
  (package
    (name "sanctify-php")
    (version "0.2.0")
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url "https://github.com/hyperpolymath/sanctify-php")
                    (commit (string-append "v" version))))
              (sha256 (base32 "..."))))
    (build-system haskell-build-system)
    (inputs (list ghc-megaparsec ghc-aeson ghc-prettyprinter))
    (synopsis "PHP security hardening and analysis tool")
    (description "Static analyzer that detects vulnerabilities and
transforms PHP code for security compliance.")
    (license (list license:expat license:agpl3+))
    (home-page "https://github.com/hyperpolymath/sanctify-php")))
```

---

## Phase 2: Semantic Web Support

**Goal**: First-class support for RDF/Turtle/JSON-LD output contexts

### 2.1 Semantic Output Detection

Add detection for semantic web output patterns:

```haskell
-- src/Sanctify/Analysis/Semantic.hs
-- SPDX-License-Identifier: AGPL-3.0-or-later

module Sanctify.Analysis.Semantic
  ( SemanticContext(..)
  , detectSemanticContext
  , semanticEscapingRules
  ) where

data SemanticContext
  = TurtleContext      -- RDF Turtle output
  | JsonLdContext      -- JSON-LD output
  | NTriplesContext    -- N-Triples output
  | RdfXmlContext      -- RDF/XML output
  | MicroformatsContext -- Microformats2 in HTML
  | NoSemanticContext  -- Standard HTML/text
  deriving (Eq, Show, Generic)

-- Detect context from surrounding code
detectSemanticContext :: Statement -> Maybe SemanticContext
detectSemanticContext stmt = case stmt of
  -- Detect Content-Type headers
  FunctionCall "header" [StringLit ct]
    | "text/turtle" `isInfixOf` ct -> Just TurtleContext
    | "application/ld+json" `isInfixOf` ct -> Just JsonLdContext
    | "application/n-triples" `isInfixOf` ct -> Just NTriplesContext

  -- Detect file extensions in output
  FunctionCall "file_put_contents" [StringLit path, _]
    | ".ttl" `isSuffixOf` path -> Just TurtleContext
    | ".jsonld" `isSuffixOf` path -> Just JsonLdContext

  -- Detect semantic template patterns
  Echo (StringLit template)
    | "@prefix" `isInfixOf` template -> Just TurtleContext
    | "\"@context\"" `isInfixOf` template -> Just JsonLdContext

  _ -> Nothing
```

### 2.2 Semantic-Aware Taint Sinks

Extend taint analysis with semantic sinks:

```haskell
-- In Sanctify.Analysis.Taint

data SemanticSink
  = TurtleLiteral      -- String literal in Turtle
  | TurtleIRI          -- IRI in Turtle
  | JsonLdValue        -- Value in JSON-LD
  | JsonLdId           -- @id field in JSON-LD
  deriving (Eq, Show)

semanticSinkEscaping :: SemanticSink -> [Text]
semanticSinkEscaping = \case
  TurtleLiteral ->
    [ "Aegis\\Semantic\\Turtle::escapeString"
    , "sanctify_escape_turtle_string"  -- WP helper
    ]
  TurtleIRI ->
    [ "Aegis\\Semantic\\Turtle::escapeIRI"
    , "sanctify_escape_turtle_iri"
    ]
  JsonLdValue ->
    [ "json_encode"  -- with JSON_HEX_* flags
    , "Aegis\\Semantic\\JsonLd::escapeValue"
    ]
  JsonLdId ->
    [ "Aegis\\Semantic\\JsonLd::validateIRI"
    , "filter_var" -- with FILTER_VALIDATE_URL
    ]
```

### 2.3 WordPress Semantic Theme Detection

Detect semantic WordPress themes:

```haskell
-- In Sanctify.WordPress.Constraints

data ThemeType
  = StandardTheme
  | SemanticTheme      -- Uses RDF/Turtle output
  | IndieWebTheme      -- Uses IndieWeb protocols
  | SemanticIndieWeb   -- Both semantic + IndieWeb
  deriving (Eq, Show)

detectThemeType :: [FilePath] -> IO ThemeType
detectThemeType files = do
  hasSemanticPhp <- any ("semantic.php" `isSuffixOf`) files
  hasIndiewebPhp <- any ("indieweb.php" `isSuffixOf`) files
  hasTurtleOutput <- anyM containsTurtlePatterns files
  hasMicropub <- anyM containsMicropubPatterns files

  pure $ case (hasSemanticPhp || hasTurtleOutput, hasIndiewebPhp || hasMicropub) of
    (True, True)  -> SemanticIndieWeb
    (True, False) -> SemanticTheme
    (False, True) -> IndieWebTheme
    _             -> StandardTheme
```

---

## Phase 3: PHP 8.x Syntax Completeness

**Goal**: Full support for PHP 8.0-8.4 syntax

### 3.1 Parser Enhancements

| Feature | PHP Version | Status | Priority |
|---------|-------------|--------|----------|
| Named arguments | 8.0 | ✅ Parsed | - |
| Match expressions | 8.0 | ✅ AST ready | Medium |
| Union types | 8.0 | ✅ Supported | - |
| Nullsafe operator `?->` | 8.0 | ⚠️ Partial | High |
| Constructor promotion | 8.0 | ✅ Supported | - |
| Intersection types | 8.1 | ✅ Supported | - |
| Readonly properties | 8.1 | ✅ Supported | - |
| Enums | 8.1 | ⚠️ Partial | High |
| First-class callables | 8.1 | ❌ Missing | Medium |
| Readonly classes | 8.2 | ❌ Missing | Medium |
| DNF types | 8.2 | ❌ Missing | Low |
| `#[\Override]` attribute | 8.3 | ❌ Missing | Low |
| Typed class constants | 8.3 | ❌ Missing | Medium |

### 3.2 Enum Support

```haskell
-- Extend AST for PHP 8.1 enums
data EnumDeclaration = EnumDeclaration
  { enumName :: Text
  , enumBackingType :: Maybe PHPType  -- int | string
  , enumCases :: [EnumCase]
  , enumMethods :: [MethodDeclaration]
  , enumImplements :: [Text]
  }
  deriving (Eq, Show, Generic)

data EnumCase = EnumCase
  { caseName :: Text
  , caseValue :: Maybe Expression  -- For backed enums
  }
  deriving (Eq, Show, Generic)
```

### 3.3 Nullsafe Operator

```haskell
-- Add nullsafe property access
data Expression
  = ...
  | PropertyAccess Expression Text        -- $obj->prop
  | NullsafePropertyAccess Expression Text -- $obj?->prop
  | MethodCall Expression Text [Argument]
  | NullsafeMethodCall Expression Text [Argument]  -- $obj?->method()
  ...
```

---

## Phase 4: WordPress Integration

**Goal**: Comprehensive WordPress integration documentation and tooling

### 4.1 WordPress Integration Guide

Create `docs/WORDPRESS.md`:

```markdown
# WordPress Integration Guide

## Quick Start

### Using Pre-built Binary

\`\`\`bash
# Download for your platform
curl -LO https://github.com/hyperpolymath/sanctify-php/releases/latest/download/sanctify-php-linux-x86_64
chmod +x sanctify-php-linux-x86_64
sudo mv sanctify-php-linux-x86_64 /usr/local/bin/sanctify-php

# Analyze your theme
sanctify-php analyze ./wp-content/themes/my-theme/
\`\`\`

### Using Docker

\`\`\`bash
docker run --rm -v $(pwd)/wp-content:/src \
  ghcr.io/hyperpolymath/sanctify-php analyze /src/themes/my-theme
\`\`\`

## CI/CD Integration

### GitHub Actions

\`\`\`yaml
name: Security Analysis
on: [push, pull_request]

jobs:
  sanctify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hyperpolymath/sanctify-php-action@v1
        with:
          path: ./wp-content/themes/my-theme
          format: sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sanctify-results.sarif
\`\`\`

## Configuration

Create `sanctify.json` in theme root:

\`\`\`json
{
  "wordpress": true,
  "theme_type": "semantic",
  "strict_types": "enforce",
  "escaping": {
    "semantic_context": true,
    "indieweb": true
  }
}
\`\`\`
```

### 4.2 GitHub Action

Create reusable GitHub Action:

```yaml
# action.yml
name: 'Sanctify PHP'
description: 'PHP security analysis and hardening'
inputs:
  path:
    description: 'Path to analyze'
    required: true
  format:
    description: 'Output format (text, json, sarif, html)'
    default: 'text'
  fix:
    description: 'Apply automatic fixes'
    default: 'false'
runs:
  using: 'docker'
  image: 'Dockerfile'
  args:
    - analyze
    - ${{ inputs.path }}
    - --format=${{ inputs.format }}
```

### 4.3 Composer Integration

For projects using Composer:

```json
{
  "scripts": {
    "security:analyze": "sanctify-php analyze ./src",
    "security:fix": "sanctify-php fix ./src --policy=conservative",
    "security:report": "sanctify-php report ./src --format=html -o security-report.html"
  }
}
```

---

## Phase 5: php-aegis Integration

**Goal**: Seamless integration with php-aegis runtime library

### 5.1 Recognize php-aegis as Safe

```haskell
-- Add php-aegis functions to safe function registry
aegisSafeFunctions :: Map Text SafetyLevel
aegisSafeFunctions = Map.fromList
  [ ("Aegis\\Escape::html", SafeForHtml)
  , ("Aegis\\Escape::attr", SafeForAttribute)
  , ("Aegis\\Escape::url", SafeForUrl)
  , ("Aegis\\Escape::js", SafeForJs)
  , ("Aegis\\Semantic\\Turtle::escapeString", SafeForTurtleLiteral)
  , ("Aegis\\Semantic\\Turtle::escapeIRI", SafeForTurtleIRI)
  , ("Aegis\\IndieWeb\\Micropub::sanitizeContent", SafeForHtml)
  ]
```

### 5.2 Auto-Insert php-aegis Calls

Transform detected vulnerabilities to use php-aegis:

```haskell
-- In Sanctify.Transform.Sanitize

insertAegisEscaping :: TaintedSink -> Expression -> Expression
insertAegisEscaping sink expr = case sink of
  HtmlOutput ->
    FunctionCall "\\Aegis\\Escape::html" [expr]

  TurtleLiteralOutput ->
    FunctionCall "\\Aegis\\Semantic\\Turtle::escapeString" [expr]

  TurtleIRIOutput ->
    FunctionCall "\\Aegis\\Semantic\\Turtle::escapeIRI" [expr]

  MicropubContent ->
    FunctionCall "\\Aegis\\IndieWeb\\Micropub::sanitizeContent" [expr]

  _ -> expr  -- Fallback to WordPress functions
```

### 5.3 Configuration Option

```json
{
  "transforms": {
    "escaping_library": "php-aegis",  // or "wordpress" or "custom"
    "fallback_to_wordpress": true
  }
}
```

---

## Timeline & Milestones

| Phase | Focus | Target Version |
|-------|-------|----------------|
| Phase 1 | Distribution | v0.2.0 |
| Phase 2 | Semantic Web | v0.3.0 |
| Phase 3 | PHP 8.x Complete | v0.4.0 |
| Phase 4 | WordPress Integration | v0.5.0 |
| Phase 5 | php-aegis Integration | v1.0.0 |

---

## Contributing

We welcome contributions! Priority areas:

1. **Distribution**: CI/CD for binary releases
2. **Parser**: PHP 8.1+ enum support
3. **Semantic**: RDF/Turtle detection and escaping rules
4. **Documentation**: WordPress integration examples

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

*SPDX-License-Identifier: PMPL-1.0-or-later
*SPDX-FileCopyrightText: 2024-2025 hyperpolymath*
