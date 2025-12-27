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

## Tracking

| Issue | Repository | Reported | Status |
|-------|------------|----------|--------|
| php-aegis-compat missing | php-aegis | 🔲 Pending | - |
| Not on Packagist | php-aegis | 🔲 Pending | - |
| mu-plugin not implemented | php-aegis | 🔲 Pending | - |
| Missing Permissions-Policy | php-aegis | 🔲 Pending | - |
| UnsafeRedirect false positive | sanctify-php | 🔲 Pending | - |
| MissingTextDomain false positive | sanctify-php | 🔲 Pending | - |
| PHP 8.1+ syntax verification | sanctify-php | 🔲 Pending | - |
| Guix export docs incomplete | sanctify-php | 🔲 Pending | - |

---

*SPDX-License-Identifier: MIT OR AGPL-3.0-or-later*
*SPDX-FileCopyrightText: 2024-2025 hyperpolymath*
