{-# LANGUAGE StrictData #-}
-- SPDX-License-Identifier: AGPL-3.0-or-later
module Sanctify.Transform.Strict
    ( transformStrict
    , transformWordPressSecurity
    ) where

import Sanctify.AST
import Sanctify.Transform.StrictTypes

-- | Add strict types to a PHP file.
transformStrict :: PhpFile -> PhpFile
transformStrict = addStrictTypes

-- | Apply WordPress-specific hardening (ABSPATH + admin checks).
transformWordPressSecurity :: PhpFile -> PhpFile
transformWordPressSecurity file =
    addAbspathCheck file
