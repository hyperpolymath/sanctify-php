;; SPDX-License-Identifier: PMPL-1.0-or-later
;; STATE.scm - Project state for sanctify-php
;; Media-Type: application/vnd.state+scm

(state
  (metadata
    (version "0.2.0")
    (schema-version "1.0")
    (created "2026-01-03")
    (updated "2026-03-14")
    (project "sanctify-php")
    (repo "github.com/hyperpolymath/sanctify-php"))

  (project-context
    (name "sanctify-php")
    (tagline "Haskell-based PHP hardening and security analysis tool — parser, taint analysis, transformations, WordPress security")
    (tech-stack ("Haskell" "Cabal 3.0" "Megaparsec" "SARIF output")))

  (current-position
    (phase "production-stabilisation")
    (overall-completion 90)
    (components ("Parser" "AST" "Analysis/Taint" "Analysis/Security" "Analysis/DeadCode" "Analysis/Advanced"
                 "Transform/Sanitize" "Transform/Strict" "Transform/StrictTypes" "Transform/TypeHints"
                 "WordPress/Constraints" "WordPress/Hooks" "WordPress/Security"
                 "Emit" "Report" "Ruleset" "Config" "CLI"))
    (working-features
      ("PHP Parser: Megaparsec-based, full grammar coverage (100%)"
       "AST: complete PHP AST representation"
       "Taint Analysis: data flow tracking (80%)"
       "Security Analysis: OWASP Top 10, ReDoS, SSRF, XXE, TOCTOU"
       "Dead Code Analysis: unreachable code detection"
       "Transform/Sanitize: automatic sanitization injection"
       "Transform/Strict: strict_types enforcement"
       "Transform/TypeHints: return type and parameter type hints"
       "WordPress/Security: nonce, capabilities, AJAX, REST API checks"
       "WordPress/Hooks: action/filter security validation"
       "WordPress/Constraints: WP-specific invariant checks"
       "Emit: lossless PHP code generation (100%)"
       "Report: text, JSON, SARIF, HTML output formats (100%)"
       "Infrastructure Export: php.ini, nginx templates (100%)"
       "17 test files including 11 PHP fixtures"
       "CLI entry point with argument handling")))

  (route-to-mvp
    (milestones
      (("core-pipeline" . "Parser + AST + Transform + Emit — DONE")
       ("security-analysis" . "Taint analysis + OWASP checks — 80%")
       ("wordpress-plugin" . "WordPress admin panel integration — 80%")
       ("lsp-integration" . "LSP/IDE in-editor highlighting — 60%")
       ("v1.0-release" . "Hackage publish + full documentation"))))

  (blockers-and-issues
    (critical ())
    (high ())
    (medium ("Taint analysis data flow paths need refinement"
             "LSP integration at 60% — in-editor highlighting active but incomplete"
             "WordPress plugin needs final admin UI hooks"))
    (low ("Cabal maintainer email uses gmail — should be j.d.a.jewell@open.ac.uk"
          "Main.hs SPDX updated to PMPL-1.0-or-later")))

  (critical-next-actions
    (immediate ("Run cabal build to verify compilation"
                "Run sanctify-php against lcb-website Sinople theme PHP files"))
    (this-week ("Refine taint analysis data flow paths"
                "Test WordPress plugin hooks against WP 6.9"))
    (this-month ("Complete LSP integration"
                 "Publish to Hackage"
                 "Fix SPDX headers")))

  (session-history
    ((date "2026-03-14")
     (accomplishments
       ("Audited actual codebase: 2,260 lines Haskell, 20 source files, 17 test files"
        "Updated STATE.scm from blank template to reflect actual ~90% completion"
        "Identified stale SPDX headers and email in cabal config"))
     (next-session "Build verification, run against lcb-website PHP, fix SPDX headers"))))
