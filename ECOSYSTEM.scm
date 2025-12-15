;; SPDX-License-Identifier: AGPL-3.0-or-later
;; SPDX-FileCopyrightText: 2025 Jonathan D.A. Jewell
;; ECOSYSTEM.scm — sanctify-php

(ecosystem
  (version "1.0.0")
  (name "sanctify-php")
  (type "project")
  (purpose "Haskell-based PHP hardening and security analysis tool.")

  (position-in-ecosystem
    "Part of hyperpolymath ecosystem. Follows RSR guidelines.")

  (related-projects
    (project (name "rhodium-standard-repositories")
             (url "https://github.com/hyperpolymath/rhodium-standard-repositories")
             (relationship "standard")))

  (what-this-is "Haskell-based PHP hardening and security analysis tool.")
  (what-this-is-not "- NOT exempt from RSR compliance"))
