# IndieWeb Security: Cross-Project Collaboration

This document outlines how `indieweb2-bastion`, `php-aegis`, and `sanctify-php` can work together to provide comprehensive IndieWeb security at both infrastructure and application layers.

---

## The IndieWeb Security Gap

IndieWeb protocols (Micropub, Webmention, IndieAuth, Microsub) have **no dedicated security libraries**. Current state:

| Protocol | Security Needs | Current Solutions | Gap |
|----------|---------------|-------------------|-----|
| **Micropub** | Content sanitization, auth verification | WordPress `wp_kses_post()` | No protocol-specific sanitization |
| **Webmention** | Rate limiting, source validation | Manual implementation | No standard library |
| **IndieAuth** | Token verification, scope validation | Various implementations | No unified validation |
| **Microsub** | Feed sanitization, auth | Minimal | Almost nothing |

### Real Vulnerabilities Found

From the Sinople integration:

```
CRITICAL: addslashes() used for Turtle escaping → RDF injection
HIGH: URL validation via strpos() → Bypass possible
HIGH: Unsanitized Micropub input → XSS in content
MEDIUM: No Webmention rate limiting → DoS vector
```

---

## Three-Layer Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    indieweb2-bastion                             │
│                  (Infrastructure Layer)                          │
├─────────────────────────────────────────────────────────────────┤
│  • Ingress gateway with IndieWeb protocol awareness              │
│  • Rate limiting at network level                                │
│  • Content-Type validation                                       │
│  • Malformed request blocking                                    │
│  • DNS-level protections (ODNS)                                  │
│  • Provenance tracking of requests                               │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                       php-aegis                                  │
│                   (Application Layer)                            │
├─────────────────────────────────────────────────────────────────┤
│  • Micropub content sanitization                                 │
│  • Webmention source validation                                  │
│  • IndieAuth token verification                                  │
│  • Turtle/RDF escaping for semantic output                       │
│  • Runtime security functions                                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                      sanctify-php                                │
│                    (Analysis Layer)                              │
├─────────────────────────────────────────────────────────────────┤
│  • Static analysis for IndieWeb security patterns               │
│  • Detect missing Micropub sanitization                          │
│  • Warn on incorrect escaping context (HTML vs Turtle)          │
│  • CI/CD integration for security gates                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Proposed indieweb2-bastion Enhancements

### 1. IndieWeb Protocol Detection

Add protocol-aware ingress rules:

```nickel
# indieweb-protocols.ncl
let IndieWebProtocol = {
  micropub = {
    endpoint = "/micropub",
    methods = ["POST", "GET"],
    content_types = ["application/json", "application/x-www-form-urlencoded", "multipart/form-data"],
    required_headers = ["Authorization"],
    rate_limit = { requests = 60, window_seconds = 60 },
  },

  webmention = {
    endpoint = "/webmention",
    methods = ["POST"],
    content_types = ["application/x-www-form-urlencoded"],
    required_params = ["source", "target"],
    rate_limit = { requests = 10, window_seconds = 60 },  # Stricter for external
  },

  indieauth = {
    endpoints = {
      authorization = "/auth",
      token = "/token",
      introspection = "/introspect",
    },
    methods = ["GET", "POST"],
    rate_limit = { requests = 30, window_seconds = 60 },
  },

  microsub = {
    endpoint = "/microsub",
    methods = ["GET", "POST"],
    required_headers = ["Authorization"],
    rate_limit = { requests = 120, window_seconds = 60 },
  },

  turtle_feed = {
    endpoint = "/feed/turtle",
    methods = ["GET"],
    response_content_type = "text/turtle",
    rate_limit = { requests = 300, window_seconds = 60 },
  },
}
in IndieWebProtocol
```

### 2. Webmention Source Validation at Ingress

Block obviously malicious Webmentions before they reach the application:

```nickel
# webmention-validation.ncl
let WebmentionPolicy = {
  # Block private/local IPs as source
  blocked_source_ranges = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "::1/128",
    "fc00::/7",
  ],

  # Require HTTPS sources
  require_https_source = true,

  # Block known spam domains
  blocked_domains_file = "/etc/bastion/webmention-blocklist.txt",

  # Require source and target on same TLD? (optional)
  same_tld_only = false,

  # Maximum source URL length
  max_url_length = 2048,
}
in WebmentionPolicy
```

### 3. Micropub Request Validation

Validate Micropub requests at the gateway:

```nickel
# micropub-validation.ncl
let MicropubPolicy = {
  # Required: Bearer token in Authorization header
  require_authorization = true,

  # Allowed actions
  allowed_actions = ["create", "update", "delete", "undelete"],

  # Content limits
  max_content_length = 65536,  # 64KB
  max_photo_size = 10485760,   # 10MB
  max_photos = 10,

  # Blocked HTML elements in content (defense in depth)
  blocked_elements = ["script", "iframe", "object", "embed", "form"],

  # Rate limits by action
  rate_limits = {
    create = { requests = 30, window_seconds = 60 },
    update = { requests = 60, window_seconds = 60 },
    delete = { requests = 10, window_seconds = 60 },
  },
}
in MicropubPolicy
```

### 4. IndieAuth Token Introspection Cache

Cache token introspection results to reduce auth server load:

```nickel
# indieauth-cache.ncl
let IndieAuthCache = {
  # Cache valid tokens
  cache_valid_tokens = true,
  valid_token_ttl_seconds = 300,  # 5 minutes

  # Don't cache invalid tokens (security)
  cache_invalid_tokens = false,

  # Introspection endpoint discovery
  discover_introspection_endpoint = true,

  # Fallback if no introspection endpoint
  fallback_to_token_endpoint = true,

  # Required scopes by endpoint
  required_scopes = {
    "/micropub" = ["create", "update", "delete", "media"],
    "/microsub" = ["read", "follow", "mute", "block", "channels"],
  },
}
in IndieAuthCache
```

### 5. Provenance Tracking for IndieWeb

Track the origin and flow of IndieWeb requests:

```surql
-- SurrealDB schema for IndieWeb provenance

DEFINE TABLE webmention_provenance SCHEMAFULL;
DEFINE FIELD source ON webmention_provenance TYPE string;
DEFINE FIELD target ON webmention_provenance TYPE string;
DEFINE FIELD source_ip ON webmention_provenance TYPE string;
DEFINE FIELD received_at ON webmention_provenance TYPE datetime;
DEFINE FIELD verified_at ON webmention_provenance TYPE option<datetime>;
DEFINE FIELD verification_status ON webmention_provenance TYPE string;
DEFINE FIELD content_hash ON webmention_provenance TYPE string;

DEFINE TABLE micropub_provenance SCHEMAFULL;
DEFINE FIELD client_id ON micropub_provenance TYPE string;
DEFINE FIELD action ON micropub_provenance TYPE string;
DEFINE FIELD post_url ON micropub_provenance TYPE option<string>;
DEFINE FIELD created_at ON micropub_provenance TYPE datetime;
DEFINE FIELD token_scope ON micropub_provenance TYPE array<string>;
DEFINE FIELD content_hash ON micropub_provenance TYPE string;

-- Relationships
DEFINE TABLE caused_by SCHEMAFULL;
DEFINE FIELD in ON caused_by TYPE record;
DEFINE FIELD out ON caused_by TYPE record;
DEFINE FIELD relationship ON caused_by TYPE string;
```

---

## Integration with php-aegis

indieweb2-bastion provides infrastructure-level protection; php-aegis handles application-level security:

### Shared Configuration

```json
{
  "indieweb_security": {
    "bastion": {
      "enabled": true,
      "trust_bastion_headers": true,
      "bastion_verified_header": "X-Bastion-Verified"
    },
    "aegis": {
      "micropub_sanitization": true,
      "webmention_validation": true,
      "turtle_escaping": true
    }
  }
}
```

### Header Passthrough

When bastion validates a request, it adds headers that php-aegis can trust:

```
X-Bastion-Verified: true
X-Bastion-Protocol: micropub
X-Bastion-Rate-Limit-Remaining: 45
X-Bastion-Source-Validated: true
X-Bastion-Request-ID: uuid-for-provenance
```

### php-aegis IndieWeb Module

```php
<?php
declare(strict_types=1);
// SPDX-License-Identifier: PMPL-1.0-or-later

namespace Aegis\IndieWeb;

final class Micropub
{
    /**
     * Sanitize Micropub content.
     * Trusts bastion pre-validation if header present.
     */
    public static function sanitizeContent(
        string $content,
        array $allowedHtml = ['a', 'p', 'br', 'strong', 'em', 'blockquote', 'ul', 'ol', 'li']
    ): string {
        // If bastion pre-validated, we can be less aggressive
        $bastionVerified = $_SERVER['HTTP_X_BASTION_VERIFIED'] ?? 'false';

        if ($bastionVerified === 'true') {
            // Bastion already blocked script/iframe/etc
            return wp_kses($content, array_fill_keys($allowedHtml, []));
        }

        // Full sanitization if no bastion
        return wp_kses_post($content);
    }
}

final class Webmention
{
    /**
     * Validate webmention source.
     * Trusts bastion source validation if present.
     */
    public static function validateSource(string $source, string $target): bool
    {
        // Check bastion pre-validation
        if (($_SERVER['HTTP_X_BASTION_SOURCE_VALIDATED'] ?? '') === 'true') {
            return true;
        }

        // Full validation
        $sourceHost = parse_url($source, PHP_URL_HOST);
        $targetHost = parse_url($target, PHP_URL_HOST);

        // Basic checks
        if (!$sourceHost || !$targetHost) return false;
        if ($sourceHost === $targetHost) return false;  // Self-mention
        if (!filter_var($source, FILTER_VALIDATE_URL)) return false;

        // Require HTTPS
        if (parse_url($source, PHP_URL_SCHEME) !== 'https') return false;

        return true;
    }
}
```

---

## Integration with sanctify-php

sanctify-php detects missing IndieWeb security patterns:

### IndieWeb-Aware Analysis

```haskell
-- src/Sanctify/IndieWeb/Analysis.hs
-- SPDX-License-Identifier: AGPL-3.0-or-later

module Sanctify.IndieWeb.Analysis
  ( detectIndieWebEndpoints
  , checkMicropubSecurity
  , checkWebmentionSecurity
  ) where

-- Detect IndieWeb endpoints by URL patterns and headers
detectIndieWebEndpoints :: [Statement] -> [IndieWebEndpoint]
detectIndieWebEndpoints stmts =
  mapMaybe detectEndpoint stmts
  where
    detectEndpoint (FunctionCall "add_action" [StringLit hook, _])
      | "micropub" `isInfixOf` hook = Just MicropubEndpoint
      | "webmention" `isInfixOf` hook = Just WebmentionEndpoint
    detectEndpoint _ = Nothing

-- Check Micropub endpoint security
checkMicropubSecurity :: MicropubEndpoint -> [SecurityIssue]
checkMicropubSecurity endpoint = concat
  [ checkAuthVerification endpoint
  , checkContentSanitization endpoint
  , checkBastionIntegration endpoint
  ]

-- Warn if not checking bastion headers when available
checkBastionIntegration :: Endpoint -> [SecurityIssue]
checkBastionIntegration endpoint
  | usesBastionHeaders endpoint = []
  | otherwise = [Advisory "Consider trusting X-Bastion-Verified for defense in depth"]
```

---

## Issue Template for indieweb2-bastion

```markdown
## Feature Request: IndieWeb Protocol Support

### Summary
Add native support for IndieWeb protocols (Micropub, Webmention, IndieAuth, Microsub)
at the bastion ingress layer.

### Motivation
IndieWeb protocols have unique security requirements:
- Webmention: Source validation, rate limiting for external requests
- Micropub: Content limits, authorization verification
- IndieAuth: Token caching, scope validation

Currently, all security is handled at the application layer. Adding bastion-level
protection provides defense in depth and reduces load on applications.

### Proposed Implementation

1. **Protocol detection** (Nickel contracts)
   - Detect IndieWeb endpoints by path/headers
   - Apply protocol-specific policies

2. **Webmention validation**
   - Block private IP sources
   - Require HTTPS
   - Rate limit by source domain

3. **Micropub limits**
   - Content size limits
   - Photo count/size limits
   - Blocked HTML elements

4. **IndieAuth integration**
   - Token introspection caching
   - Scope validation at ingress

5. **Provenance tracking**
   - SurrealDB schema for IndieWeb events
   - Request correlation with application events

### Integration Points
- php-aegis: Trust bastion headers for reduced sanitization
- sanctify-php: Detect bastion integration, warn if missing

### Reference
See: hyperpolymath/sanctify-php/docs/INDIEWEB-COLLABORATION.md
```

---

## Lessons Exchanged

### FROM indieweb2-bastion TO php-aegis/sanctify-php

| Concept | Application |
|---------|-------------|
| **Nickel contracts** | Define security policies declaratively for sanctify-php |
| **Provenance graphs** | Track sanitization chain (who sanitized what, when) |
| **Consent-aware** | IndieWeb is about user control - reflect in API design |
| **Rate limiting patterns** | Apply at application level as fallback |

### TO indieweb2-bastion FROM php-aegis/sanctify-php

| Finding | Recommendation |
|---------|---------------|
| **Turtle escaping gap** | Validate Content-Type for /feed/turtle endpoints |
| **Webmention abuse** | Add source validation at ingress |
| **Micropub content** | Block dangerous HTML elements before application |
| **Real vulnerability found** | addslashes() misuse - validate escaping context |

---

## Next Steps

1. **Open issue on indieweb2-bastion** with the template above
2. **Create shared Nickel contracts** for IndieWeb security policies
3. **Add bastion header support** to php-aegis IndieWeb module
4. **Extend sanctify-php** to detect bastion integration

---

*SPDX-License-Identifier: PMPL-1.0-or-later
*SPDX-FileCopyrightText: 2024-2025 hyperpolymath*
