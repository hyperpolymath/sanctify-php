<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->
<!-- TOPOLOGY.md — Project architecture map and completion dashboard -->
<!-- Last updated: 2026-02-19 -->

# Sanctify-PHP — Project Topology

## System Architecture

```
                        ┌─────────────────────────────────────────┐
                        │              PHP DEVELOPER              │
                        │        (CLI, LSP, WordPress Plugin)     │
                        └───────────────────┬─────────────────────┘
                                            │ PHP Source
                                            ▼
                        ┌─────────────────────────────────────────┐
                        │           SANCTIFY-PHP CORE (HASKELL)   │
                        │                                         │
                        │  ┌───────────┐  ┌───────────────────┐  │
                        │  │  Parser   │──►   AST Analysis    │  │
                        │  │ (Megapars)│  │ (Types/Taint)     │  │
                        │  └─────┬─────┘  └────────┬──────────┘  │
                        │        │                 │              │
                        │  ┌─────▼─────┐  ┌────────▼──────────┐  │
                        │  │ Transform │  │  Emit / Report    │  │
                        │  │ Passes    │  │ (SARIF/HTML/PHP)  │  │
                        │  └─────┬─────┘  └────────┬──────────┘  │
                        └────────│─────────────────│──────────────┘
                                 │                 │
                                 ▼                 ▼
                        ┌─────────────────────────────────────────┐
                        │           OUTPUT ARTIFACTS              │
                        │  ┌───────────┐  ┌───────────┐  ┌───────┐│
                        │  │ Hardened  │  │ Security  │  │ Infra ││
                        │  │ PHP Code  │  │ Reports   │  │ Config││
                        │  └───────────┘  └───────────┘  └───────┘│
                        └───────────────────┬─────────────────────┘
                                            │
                                            ▼
                        ┌─────────────────────────────────────────┐
                        │           TARGET ENVIRONMENT            │
                        │      (WordPress, Nginx, Guix/Aegis)     │
                        └─────────────────────────────────────────┘

                        ┌─────────────────────────────────────────┐
                        │          REPO INFRASTRUCTURE            │
                        │  Justfile Automation  .machine_readable/  │
                        │  Cabal / Nix / Guix   0-AI-MANIFEST.a2ml  │
                        └─────────────────────────────────────────┘
```

## Completion Dashboard

```
COMPONENT                          STATUS              NOTES
─────────────────────────────────  ──────────────────  ─────────────────────────────────
CORE PIPELINE (HASKELL)
  PHP Parser (Megaparsec)           ██████████ 100%    Full grammar coverage stable
  AST & Taint Analysis              ████████░░  80%    Data flow paths refining
  Transformation Passes             ██████████ 100%    strict_types/ABSPATH verified
  PHP Code Emission                 ██████████ 100%    Lossless generation verified

INTEGRATIONS
  LSP / IDE Integration             ██████░░░░  60%    In-editor highlighting active
  WordPress Plugin                  ████████░░  80%    Scan & Audit hooks stable
  Infrastructure Export             ██████████ 100%    Nginx/php.ini templates active

REPO INFRASTRUCTURE
  Justfile Automation               ██████████ 100%    Standard build/test tasks
  .machine_readable/                ██████████ 100%    STATE tracking active
  Guix / Nix Build                  ██████████ 100%    Reproducible build env stable

─────────────────────────────────────────────────────────────────────────────
OVERALL:                            █████████░  ~90%   Stable security toolkit
```

## Key Dependencies

```
PHP Source ──────► Haskell Parser ────► AST Analysis ──────► Transform
     │                 │                   │                    │
     ▼                 ▼                   ▼                    ▼
Target Env ◄────── Emit Code ◄─────── Infrastructure ◄───── Report
```

## Update Protocol

This file is maintained by both humans and AI agents. When updating:

1. **After completing a component**: Change its bar and percentage
2. **After adding a component**: Add a new row in the appropriate section
3. **After architectural changes**: Update the ASCII diagram
4. **Date**: Update the `Last updated` comment at the top of this file

Progress bars use: `█` (filled) and `░` (empty), 10 characters wide.
Percentages: 0%, 10%, 20%, ... 100% (in 10% increments).
