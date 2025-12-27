-- | Test suite for Sanctify PHP
-- SPDX-License-Identifier: AGPL-3.0-or-later
module Main (main) where

import Test.Hspec
import Data.Text (Text)
import qualified Data.Text as T

import Sanctify.Parser
import Sanctify.AST
import Sanctify.Analysis.DeadCode

main :: IO ()
main = hspec $ do
    describe "Sanctify.Analysis.DeadCode" $ do
        deadCodeSpecs

deadCodeSpecs :: Spec
deadCodeSpecs = do
    describe "analyzeDeadCode" $ do
        it "detects unused variables" $ do
            let code = T.unlines
                    [ "<?php"
                    , "$unused = 42;"
                    , "$used = 'hello';"
                    , "echo $used;"
                    ]
            case parsePhpString "test.php" code of
                Left err -> expectationFailure $ "Parse error: " ++ show err
                Right file -> do
                    let issues = analyzeDeadCode file
                        unusedVars = filter ((== UnusedVariable) . dcType) issues
                    length unusedVars `shouldBe` 1
                    dcIdentifier (head unusedVars) `shouldBe` "unused"

        it "detects unreachable code after return" $ do
            let code = T.unlines
                    [ "<?php"
                    , "function test() {"
                    , "    return 1;"
                    , "    $x = 2;"
                    , "}"
                    ]
            case parsePhpString "test.php" code of
                Left err -> expectationFailure $ "Parse error: " ++ show err
                Right file -> do
                    let issues = analyzeDeadCode file
                        unreachable = filter ((== UnreachableCode) . dcType) issues
                    length unreachable `shouldBe` 1

        it "detects unreachable code after throw" $ do
            let code = T.unlines
                    [ "<?php"
                    , "function test() {"
                    , "    throw new Exception('error');"
                    , "    $cleanup = true;"
                    , "}"
                    ]
            case parsePhpString "test.php" code of
                Left err -> expectationFailure $ "Parse error: " ++ show err
                Right file -> do
                    let issues = analyzeDeadCode file
                        unreachable = filter ((== UnreachableCode) . dcType) issues
                    length unreachable `shouldBe` 1

        it "detects unused function parameters" $ do
            let code = T.unlines
                    [ "<?php"
                    , "function greet($name, $age) {"
                    , "    return 'Hello, ' . $name;"
                    , "}"
                    ]
            case parsePhpString "test.php" code of
                Left err -> expectationFailure $ "Parse error: " ++ show err
                Right file -> do
                    let issues = analyzeDeadCode file
                        unusedParams = filter ((== UnusedParameter) . dcType) issues
                    length unusedParams `shouldBe` 1
                    dcIdentifier (head unusedParams) `shouldBe` "age"

        it "returns no issues for clean code" $ do
            let code = T.unlines
                    [ "<?php"
                    , "function add($a, $b) {"
                    , "    $sum = $a + $b;"
                    , "    return $sum;"
                    , "}"
                    ]
            case parsePhpString "test.php" code of
                Left err -> expectationFailure $ "Parse error: " ++ show err
                Right file -> do
                    let issues = analyzeDeadCode file
                    issues `shouldBe` []

        it "handles variables in closures correctly" $ do
            let code = T.unlines
                    [ "<?php"
                    , "$outer = 10;"
                    , "$fn = function() use ($outer) {"
                    , "    return $outer * 2;"
                    , "};"
                    , "$result = $fn();"
                    , "echo $result;"
                    ]
            case parsePhpString "test.php" code of
                Left err -> expectationFailure $ "Parse error: " ++ show err
                Right file -> do
                    let issues = analyzeDeadCode file
                        unusedVars = filter ((== UnusedVariable) . dcType) issues
                    -- $outer and $result should be marked as used, $fn should be used
                    unusedVars `shouldBe` []

        it "detects multiple unused variables" $ do
            let code = T.unlines
                    [ "<?php"
                    , "$a = 1;"
                    , "$b = 2;"
                    , "$c = 3;"
                    , "echo $a;"
                    ]
            case parsePhpString "test.php" code of
                Left err -> expectationFailure $ "Parse error: " ++ show err
                Right file -> do
                    let issues = analyzeDeadCode file
                        unusedVars = filter ((== UnusedVariable) . dcType) issues
                    length unusedVars `shouldBe` 2

    describe "findUnusedVariables" $ do
        it "filters only variable-related issues" $ do
            let code = T.unlines
                    [ "<?php"
                    , "function test($unused) {"
                    , "    $dead = 1;"
                    , "    return 0;"
                    , "    $unreachable = 2;"
                    , "}"
                    ]
            case parsePhpString "test.php" code of
                Left err -> expectationFailure $ "Parse error: " ++ show err
                Right file -> do
                    let issues = findUnusedVariables file
                    -- Should have unused parameter and unused variable, but not unreachable
                    all (\i -> dcType i `elem` [UnusedVariable, UnusedParameter]) issues
                        `shouldBe` True

    describe "findUnreachableCode" $ do
        it "filters only unreachable code issues" $ do
            let code = T.unlines
                    [ "<?php"
                    , "$unused = 1;"
                    , "return;"
                    , "$dead = 2;"
                    ]
            case parsePhpString "test.php" code of
                Left err -> expectationFailure $ "Parse error: " ++ show err
                Right file -> do
                    let issues = findUnreachableCode file
                    all (\i -> dcType i == UnreachableCode) issues `shouldBe` True
                    length issues `shouldBe` 1
