;;; ROADMAP.scm — sanctify-php Development Roadmap
;; SPDX-License-Identifier: AGPL-3.0-or-later
;; SPDX-FileCopyrightText: 2025 Jonathan D.A. Jewell
;;
;; This roadmap outlines the development phases for sanctify-php.
;; Updated: 2025-12-17

(define-module (sanctify-php roadmap)
  #:export (roadmap current-milestone next-steps))

;;; ============================================================================
;;; PHASE 1: Foundation (v0.1.x) — Current Phase
;;; ============================================================================

(define phase-1
  '((name . "Foundation")
    (version . "0.1.x")
    (status . "in-progress")
    (completion . 30)
    (milestones
     (;; COMPLETED
      (milestone "RSR Compliance"
        (status . complete)
        (items
         ("SPDX headers on all files" . done)
         ("SHA-pinned GitHub Actions" . done)
         ("Security workflows configured" . done)
         ("Guix SCM files" . done)
         ("Dual licensing (MIT/AGPL)" . done)))

      (milestone "CI/CD Security"
        (status . complete)
        (items
         ("CodeQL analysis" . done)
         ("PHP security scanning" . done)
         ("Secret detection (TruffleHog)" . done)
         ("OpenSSF Scorecard" . done)
         ("Haskell extensions in security checks" . done)
         ("Upgraded to GHC 9.6" . done)))

      ;; IN PROGRESS
      (milestone "PHP Parser"
        (status . pending)
        (priority . high)
        (items
         ("Megaparsec-based lexer" . pending)
         ("PHP 7.4+ syntax support" . pending)
         ("PHP 8.x syntax support" . pending)
         ("AST representation" . pending)
         ("Source location tracking" . pending)
         ("Error recovery" . pending)))

      (milestone "Test Infrastructure"
        (status . pending)
        (priority . medium)
        (items
         ("HSpec test suite setup" . pending)
         ("Parser unit tests" . pending)
         ("Golden tests with PHP fixtures" . pending)
         ("Property-based tests (QuickCheck)" . pending)
         ("CI test coverage reporting" . pending)))))))

;;; ============================================================================
;;; PHASE 2: Core Analysis (v0.2.x)
;;; ============================================================================

(define phase-2
  '((name . "Core Analysis")
    (version . "0.2.x")
    (status . "planned")
    (milestones
     ((milestone "Security Analysis Engine"
        (priority . critical)
        (items
         ("SQL injection detection" . planned)
         ("XSS vulnerability detection" . planned)
         ("CSRF pattern identification" . planned)
         ("Command injection detection" . planned)
         ("Path traversal detection" . planned)
         ("Unsafe deserialization detection" . planned)))

      (milestone "Taint Tracking"
        (priority . high)
        (items
         ("Source identification ($_GET, $_POST, etc.)" . planned)
         ("Sink identification (echo, query, etc.)" . planned)
         ("Data flow analysis" . planned)
         ("Sanitizer recognition" . planned)
         ("Cross-function taint propagation" . planned)))

      (milestone "Type Inference"
        (priority . medium)
        (items
         ("Return type inference" . planned)
         ("Parameter type inference" . planned)
         ("Property type inference" . planned)
         ("PHPDoc annotation parsing" . planned)
         ("Type hint suggestions" . planned)))))))

;;; ============================================================================
;;; PHASE 3: Transformations (v0.3.x)
;;; ============================================================================

(define phase-3
  '((name . "Transformations")
    (version . "0.3.x")
    (status . "planned")
    (milestones
     ((milestone "Strict Types Transformation"
        (priority . high)
        (risk . "zero")
        (items
         ("Add declare(strict_types=1)" . planned)
         ("Preserve existing declarations" . planned)
         ("Handle multiple files" . planned)))

      (milestone "Type Hint Addition"
        (priority . high)
        (risk . "low-review-required")
        (items
         ("Add inferred parameter types" . planned)
         ("Add inferred return types" . planned)
         ("Generate PHPStan annotations" . planned)
         ("Preserve formatting" . planned)))

      (milestone "Sanitization Transforms"
        (priority . critical)
        (risk . "medium-review-required")
        (items
         ("Auto-escape echo statements" . planned)
         ("wpdb::query to prepare conversion" . planned)
         ("Superglobal sanitization" . planned)
         ("rand() to random_int() upgrade" . planned)
         ("Nonce verification insertion" . planned)))

      (milestone "Code Emission"
        (priority . high)
        (items
         ("Pretty-print transformed AST" . planned)
         ("Preserve comments" . planned)
         ("Maintain original formatting where possible" . planned)
         ("Diff-friendly output" . planned)))))))

;;; ============================================================================
;;; PHASE 4: WordPress Support (v0.4.x)
;;; ============================================================================

(define phase-4
  '((name . "WordPress Support")
    (version . "0.4.x")
    (status . "planned")
    (milestones
     ((milestone "WordPress Constraints"
        (priority . high)
        (items
         ("ABSPATH check enforcement" . planned)
         ("Capability escalation detection" . planned)
         ("Direct database access warnings" . planned)
         ("Proper escaping function usage" . planned)
         ("Text domain consistency" . planned)))

      (milestone "WordPress Hooks Analysis"
        (priority . medium)
        (items
         ("Action hook analysis" . planned)
         ("Filter hook analysis" . planned)
         ("Priority conflict detection" . planned)
         ("Deprecated hook warnings" . planned)))

      (milestone "WordPress Security Patterns"
        (priority . critical)
        (items
         ("Admin-ajax.php security" . planned)
         ("REST API endpoint security" . planned)
         ("File upload handling" . planned)
         ("Options API security" . planned)
         ("User meta security" . planned)))))))

;;; ============================================================================
;;; PHASE 5: Reporting & Integration (v0.5.x)
;;; ============================================================================

(define phase-5
  '((name . "Reporting & Integration")
    (version . "0.5.x")
    (status . "planned")
    (milestones
     ((milestone "Report Generation"
        (priority . high)
        (items
         ("JSON report format" . planned)
         ("SARIF format for IDE integration" . planned)
         ("HTML report with navigation" . planned)
         ("Markdown summary" . planned)
         ("Severity classification" . planned)))

      (milestone "Infrastructure Export"
        (priority . medium)
        (items
         ("php.ini recommendations export" . planned)
         ("nginx security rules export" . planned)
         ("Guix container overrides export" . planned)
         ("Docker security configs" . planned)))

      (milestone "IDE Integration"
        (priority . medium)
        (items
         ("VSCode extension" . planned)
         ("Language Server Protocol (LSP)" . planned)
         ("Real-time analysis" . planned)
         ("Quick-fix suggestions" . planned)))))))

;;; ============================================================================
;;; PHASE 6: Production Ready (v1.0.0)
;;; ============================================================================

(define phase-6
  '((name . "Production Ready")
    (version . "1.0.0")
    (status . "planned")
    (milestones
     ((milestone "Performance Optimization"
        (items
         ("Parallel file processing" . planned)
         ("Incremental analysis" . planned)
         ("Memory optimization" . planned)
         ("Large codebase support" . planned)))

      (milestone "Documentation"
        (items
         ("User guide" . planned)
         ("API documentation" . planned)
         ("Integration examples" . planned)
         ("WordPress plugin guidelines" . planned)))

      (milestone "Release"
        (items
         ("Binary releases (Linux/macOS/Windows)" . planned)
         ("Guix package submission" . planned)
         ("Homebrew formula" . planned)
         ("Docker image" . planned)))))))

;;; ============================================================================
;;; Summary & Export
;;; ============================================================================

(define roadmap
  (list phase-1 phase-2 phase-3 phase-4 phase-5 phase-6))

(define current-milestone
  '((phase . 1)
    (name . "Foundation")
    (next-task . "Implement PHP parser with Megaparsec")
    (blockers . ())))

(define next-steps
  '(("Implement PHP lexer" . immediate)
    ("Add parser tests" . immediate)
    ("Implement AST pretty-printer" . this-week)
    ("Add strict_types transformation" . this-week)
    ("Implement basic SQL injection detection" . next-sprint)))
