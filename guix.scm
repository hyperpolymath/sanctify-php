; SPDX-License-Identifier: PMPL-1.0-or-later
;; guix.scm — GNU Guix package definition for sanctify-php
;; Usage: guix shell -f guix.scm

(use-modules (guix packages)
             (guix build-system gnu)
             (guix licenses))

(package
  (name "sanctify-php")
  (version "0.1.0")
  (source #f)
  (build-system gnu-build-system)
  (synopsis "sanctify-php")
  (description "sanctify-php — part of the hyperpolymath ecosystem.")
  (home-page "https://github.com/hyperpolymath/sanctify-php")
  (license ((@@ (guix licenses) license) "PMPL-1.0-or-later"
             "https://github.com/hyperpolymath/palimpsest-license")))
