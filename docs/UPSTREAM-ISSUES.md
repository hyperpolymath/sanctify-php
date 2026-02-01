# Upstream Issues

Issues discovered during integration testing that need to be reported to respective repositories.

---

## php-aegis Issues

### Issue 1: Missing php-aegis-compat Package

**Severity**: High
**Found in**: sinople-theme integration

**Description**:
The `COMPATIBILITY.md` documentation references a `php-aegis-compat` package for PHP 7.4+ compatibility, but this package does not exist.

**Impact**:
WordPress projects targeting PHP 7.4 (the WordPress minimum) cannot use php-aegis.

**Recommended Fix**:
```bash
# Create the package
mkdir php-aegis-compat
# Implement PHP 7.4 compatible API without enums/union types
```

---

### Issue 2: Not Published on Packagist

**Severity**: Medium
**Found in**: sinople-theme integration

**Description**:
php-aegis is not available on Packagist, requiring VCS repository configuration in composer.json.

**Current workaround**:
```json
{
    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/hyperpolymath/php-aegis"
        }
    ]
}
```

**Recommended Fix**:
Publish to Packagist for standard `composer require` experience.

---

### Issue 3: WordPress mu-plugin Adapter Not Implemented

**Severity**: Medium
**Found in**: sinople-theme integration

**Description**:
Documentation describes a WordPress mu-plugin adapter for automatic loading, but the adapter code does not exist.

**Expected location**: `src/WordPress/MuPlugin.php`

**Recommended Fix**:
Implement the mu-plugin adapter or remove from documentation.

---

### Issue 4: Headers::secure() Missing permissionsPolicy()

**Severity**: Low
**Found in**: sinople-theme integration

**Description**:
The `Headers::secure()` method sets security headers but is missing `Permissions-Policy` header.

**Current output**:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: ...
```

**Missing**:
```
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

---

## sanctify-php Issues

### Issue 1: UnsafeRedirect False Positive

**Severity**: Medium
**Found in**: sinople-theme integration

**Description**:
The `UnsafeRedirect` check flags code as unsafe even when `exit` is on the next line.

**False positive**:
```php
wp_redirect($url);
exit;  // This IS safe, but sanctify reports it as unsafe
```

**Expected behavior**:
Should recognize `exit`/`die` on the immediately following line as safe.

**Recommended Fix**:
```haskell
-- In UnsafeRedirect check, look for exit/die within next 2 statements
isFollowedByExit :: Statement -> [Statement] -> Bool
isFollowedByExit redirect following =
  case take 2 following of
    (ExitStatement:_) -> True
    (DieStatement:_) -> True
    _ -> False
```

---

### Issue 2: MissingTextDomain False Positive on WP Core

**Severity**: Low
**Found in**: sinople-theme integration

**Description**:
The `MissingTextDomain` check flags WordPress core functions that don't need a text domain.

**False positive**:
```php
// These are WordPress core, not theme strings
__('Dashboard');  // Flagged, but this is WP core
```

**Recommended Fix**:
Maintain allowlist of WordPress core strings, or only check strings in theme/plugin files.

---

### Issue 3: PHP 8.1+ Syntax Verification Needed

**Severity**: Medium
**Found in**: sinople-theme integration

**Description**:
Need to verify parser handles modern PHP syntax:
- Nullsafe operator (`?->`)
- Match expressions
- Named arguments
- Enums
- Constructor property promotion

**Recommended Fix**:
Add test suite with PHP 8.1+ syntax examples.

---

### Issue 4: Incomplete Guix Export Documentation

**Severity**: Low
**Found in**: sinople-theme integration

**Description**:
The `sanctify export --guix` command is documented but the output format and usage instructions are incomplete.

**Missing**:
- Example output
- How to integrate with existing guix.scm
- Container vs package mode

---

## Issue Template for GitHub

### php-aegis Issue Template

```markdown
## Issue: [Title]

**Found during**: sinople-theme integration
**Severity**: [High/Medium/Low]

### Description
[Description of the issue]

### Steps to Reproduce
1. [Step 1]
2. [Step 2]

### Expected Behavior
[What should happen]

### Actual Behavior
[What actually happens]

### Suggested Fix
[Code or approach to fix]
```

### sanctify-php Issue Template

```markdown
## Issue: [Title]

**Found during**: sinople-theme integration
**Severity**: [High/Medium/Low]
**Component**: [Parser/Analysis/Transform/CLI]

### Description
[Description of the issue]

### Example Code Triggering Issue
```php
// PHP code that triggers the issue
```

### Expected Behavior
[What sanctify-php should report/do]

### Actual Behavior
[What sanctify-php actually reports/does]

### Suggested Fix
[Haskell code or approach to fix]
```

---

## Issues from Sinople Full Integration

### php-aegis Issues (from Sinople)

#### Issue 5: WordPress-Specific Validators Needed

**Severity**: Medium
**Found in**: Sinople full integration

**Description**:
WordPress has security patterns (nonces, capabilities) that php-aegis doesn't address.

**Needed validators**:
```php
Aegis\WordPress\Nonce::verify($action, $nonce);
Aegis\WordPress\Capability::check($cap, $user_id);
```

---

#### Issue 6: TurtleEscaper Language Tag Case Sensitivity

**Severity**: Low
**Found in**: Sinople full integration

**Description**:
Language tags in Turtle should be case-insensitive per BCP 47, but TurtleEscaper may not handle this correctly.

---

#### Issue 7: Headers Class WordPress Integration

**Severity**: Low
**Found in**: Sinople full integration

**Description**:
`Headers::secure()` doesn't integrate with WordPress's `send_headers` action.

**Recommended**:
```php
add_action('send_headers', [Headers::class, 'secure']);
```

---

### sanctify-php Issues (from Sinople)

#### Issue 5: WordPress Hook Detection

**Severity**: Medium
**Found in**: Sinople full integration

**Description**:
sanctify-php should detect WordPress hooks (`add_action`, `add_filter`) and reduce false positives when code is wrapped in hook callbacks.

---

#### Issue 6: RDF Turtle as Distinct Output Context

**Severity**: High
**Found in**: Sinople full integration

**Description**:
Turtle output is a distinct context from HTML. sanctify-php should:
- Detect `Content-Type: text/turtle`
- Warn when `esc_html()` is used in Turtle context
- Suggest `TurtleEscaper` instead

---

#### Issue 7: WordPress REST API Pattern Recognition

**Severity**: Medium
**Found in**: Sinople full integration

**Description**:
WordPress REST API endpoints have specific sanitization patterns that sanctify-php should recognize.

---

## Tracking

| Issue | Repository | Reported | Status |
|-------|------------|----------|--------|
| php-aegis-compat missing | php-aegis | 🔲 Pending | - |
| Not on Packagist | php-aegis | 🔲 Pending | - |
| mu-plugin not implemented | php-aegis | 🔲 Pending | - |
| Missing Permissions-Policy | php-aegis | 🔲 Pending | - |
| WordPress validators needed | php-aegis | 🔲 Pending | - |
| TurtleEscaper lang tag case | php-aegis | 🔲 Pending | - |
| Headers WP integration | php-aegis | 🔲 Pending | - |
| UnsafeRedirect false positive | sanctify-php | 🔲 Pending | - |
| MissingTextDomain false positive | sanctify-php | 🔲 Pending | - |
| PHP 8.1+ syntax verification | sanctify-php | 🔲 Pending | - |
| Guix export docs incomplete | sanctify-php | 🔲 Pending | - |
| WordPress hook detection | sanctify-php | 🔲 Pending | - |
| Turtle as output context | sanctify-php | 🔲 Pending | - |
| REST API pattern recognition | sanctify-php | 🔲 Pending | - |

---

*SPDX-License-Identifier: PMPL-1.0-or-later
*SPDX-FileCopyrightText: 2024-2025 hyperpolymath*
