-- | PHP Parser using Megaparsec
-- SPDX-License-Identifier: AGPL-3.0-or-later
module Sanctify.Parser
    ( -- * Main parsing functions
      parsePhpFile
    , parsePhpString
    , parseStatement
    , parseExpr

      -- * Parser type
    , Parser
    , ParseError

      -- * Re-exports
    , PhpFile(..)
    , Statement(..)
    , Expr(..)
    ) where

import Data.Text (Text)
import qualified Data.Text as T
import Data.Maybe (isNothing)
import Data.Void (Void)
import Text.Megaparsec hiding (ParseError, SourcePos)
import Text.Megaparsec.Char
import qualified Text.Megaparsec.Char.Lexer as L
import qualified Text.Megaparsec.Pos as MPPos
import Control.Monad (void, when, unless, forM_, mapM_)
import Control.Monad.Combinators.Expr

import Sanctify.AST

-- | Parser type
type Parser = Parsec Void Text

-- | Parse error type
type ParseError = ParseErrorBundle Text Void

-- | Parse a PHP file from a file path
parsePhpFile :: FilePath -> IO (Either ParseError PhpFile)
parsePhpFile path = do
    content <- T.pack <$> readFile path
    pure $ parsePhpString path content

-- | Parse PHP from a string
parsePhpString :: FilePath -> Text -> Either ParseError PhpFile
parsePhpString = parse phpFileP

-- | Parse a single statement
parseStatement :: Text -> Either ParseError (Located Statement)
parseStatement = parse statementP "<input>"

-- | Parse a single expression
parseExpr :: Text -> Either ParseError (Located Expr)
parseExpr = parse exprP "<input>"

-- | === Lexer === ---

-- | Space consumer (skips whitespace and comments)
sc :: Parser ()
sc = L.space
    space1
    (L.skipLineComment "//")
    (L.skipBlockComment "/*" "*/")

-- | Lexeme wrapper
lexeme :: Parser a -> Parser a
lexeme = L.lexeme sc

-- | Symbol parser
symbol :: Text -> Parser Text
symbol = L.symbol sc

-- | Reserved words
reserved :: Text -> Parser ()
reserved w = (lexeme . try) (string w *> notFollowedBy alphaNumChar)

-- | Parse between braces
braces :: Parser a -> Parser a
braces = between (symbol "{") (symbol "}")

-- | Parse between parentheses
parens :: Parser a -> Parser a
parens = between (symbol "(") (symbol ")")

-- | Parse between brackets
brackets :: Parser a -> Parser a
brackets = between (symbol "[") (symbol "]")

-- | Parse a comma-separated list
commaSep :: Parser a -> Parser [a]
commaSep p = p `sepBy` symbol ","

-- | Parse a semicolon
semi :: Parser ()
semi = void $ symbol ";"

-- | === PHP Parser === ---

-- | Parse complete PHP file
phpFileP :: Parser PhpFile
phpFileP = do
    sc
    _ <- optional (symbol "<?php" <|> symbol "<?")
    sc
    strict <- option False declareStrictP
    ns <- optional namespaceP
    uses <- many useP
    stmts <- many statementP
    eof
    pure PhpFile
        { phpDeclareStrict = strict
        , phpNamespace = ns
        , phpUses = uses
        , phpStatements = stmts
        }

-- | Parse declare(strict_types=1)
declareStrictP :: Parser Bool
declareStrictP = do
    reserved "declare"
    _ <- parens $ do
        _ <- symbol "strict_types"
        _ <- symbol "="
        n <- L.decimal
        pure (n == (1 :: Int))
    semi
    pure True

-- | Parse namespace declaration
namespaceP :: Parser QualifiedName
namespaceP = do
    reserved "namespace"
    qn <- qualifiedNameP
    semi
    pure qn

-- | Parse use declaration
useP :: Parser UseDecl
useP = do
    reserved "use"
    kind <- option UseClass $ choice
        [ UseFunction <$ reserved "function"
        , UseConstant <$ reserved "const"
        ]
    name <- qualifiedNameP
    alias <- optional (reserved "as" *> nameP)
    semi
    pure UseDecl
        { useName = name
        , useAlias = alias
        , useKind = kind
        }

-- | Parse qualified name
qualifiedNameP :: Parser QualifiedName
qualifiedNameP = do
    absolute <- option False (True <$ symbol "\\")
    parts <- nameP `sepBy1` symbol "\\"
    pure QualifiedName { qnParts = parts, qnAbsolute = absolute }

-- | Parse simple name
nameP :: Parser Name
nameP = lexeme $ do
    first <- letterChar <|> char '_'
    rest <- many (alphaNumChar <|> char '_')
    pure $ Name $ T.pack (first : rest)

-- | Parse variable
variableP :: Parser Variable
variableP = lexeme $ do
    _ <- char '$'
    first <- letterChar <|> char '_'
    rest <- many (alphaNumChar <|> char '_')
    pure $ Variable $ T.pack (first : rest)

-- | Parse statement
statementP :: Parser (Located Statement)
statementP = do
    pos <- getSourcePos
    let loc = toSourcePos pos
    stmt <- choice
        [ (\(cond, thenStmts, elseStmts) -> StmtIf cond thenStmts elseStmts) <$> ifP
        , (\(cond, body) -> StmtWhile cond body) <$> whileP
        , (\(initial, cond, update, body) -> StmtFor initial cond update body) <$> forP
        , (\(expr, value, key, body) -> StmtForeach expr value key body) <$> foreachP
        , (\(expr, cases) -> StmtSwitch expr cases) <$> switchP
        , (\(expr, arms) -> StmtMatch expr arms) <$> matchP
        , (\(body, catches, finallyBlock) -> StmtTry body catches finallyBlock) <$> tryP
        , StmtReturn <$> returnP
        , StmtThrow <$> throwP
        , StmtBreak <$> breakP
        , StmtContinue <$> continueP
        , StmtEcho <$> echoP
        , StmtGlobal <$> globalP
        , StmtStatic <$> staticP
        , StmtUnset <$> unsetP
        , (\(dirs, body) -> StmtDeclare dirs body) <$> declareP
        , StmtDecl <$> declarationP
        , exprStmtP
        ]
    pure $ Located loc stmt
  where
    ifP = do
        reserved "if"
        cond <- parens exprP
        thenStmts <- braces (many statementP)
        elseStmts <- optional (reserved "else" *> braces (many statementP))
        pure (cond, thenStmts, elseStmts)

    whileP = do
        reserved "while"
        cond <- parens exprP
        body <- braces (many statementP)
        pure (cond, body)

    forP = do
        reserved "for"
        (i, c, u) <- parens $ do
            i <- optional exprP
            semi
            c <- optional exprP
            semi
            u <- optional exprP
            pure (i, c, u)
        body <- braces (many statementP)
        pure (i, c, u, body)

    foreachP = do
        reserved "foreach"
        (e, v, k) <- parens $ do
            e <- exprP
            reserved "as"
            k <- optional $ try (variableP <* symbol "=>")
            v <- variableP
            pure (e, v, k)
        body <- braces (many statementP)
        pure (e, v, k, body)

    switchP = do
        reserved "switch"
        expr <- parens exprP
        cases <- braces (many switchCaseP)
        pure (expr, cases)
      where
        switchCaseP = do
            caseExpr <- optional (reserved "case" *> exprP <* symbol ":")
            when (isNothing caseExpr) (void $ reserved "default" *> symbol ":")
            body <- many statementP
            pure SwitchCase { caseExpr = caseExpr, caseBody = body }

    -- PHP 8.0 match expression as statement
    matchP = do
        reserved "match"
        expr <- parens exprP
        arms <- braces (commaSep matchArmP)
        semi
        pure (expr, arms)
      where
        matchArmP = do
            conds <- (reserved "default" *> pure []) <|> (exprP `sepBy1` symbol ",")
            _ <- symbol "=>"
            result <- exprP
            pure MatchArm { matchConditions = conds, matchResult = result }

    tryP = do
        reserved "try"
        body <- braces (many statementP)
        catches <- many catchP
        finally <- optional (reserved "finally" *> braces (many statementP))
        pure (body, catches, finally)
      where
        catchP = do
            reserved "catch"
            (types, var) <- parens $ do
                types <- qualifiedNameP `sepBy1` symbol "|"
                var <- optional variableP
                pure (types, var)
            body <- braces (many statementP)
            pure CatchClause { catchTypes = types, catchVar = var, catchBody = body }

    throwP = do
        reserved "throw"
        e <- exprP
        semi
        pure e

    breakP = do
        reserved "break"
        n <- optional (L.decimal :: Parser Int)
        semi
        pure n

    continueP = do
        reserved "continue"
        n <- optional (L.decimal :: Parser Int)
        semi
        pure n

    returnP = do
        reserved "return"
        e <- optional exprP
        semi
        pure e

    echoP = do
        reserved "echo"
        es <- commaSep exprP
        semi
        pure es

    globalP = do
        reserved "global"
        vars <- commaSep variableP
        semi
        pure vars

    staticP = do
        reserved "static"
        vars <- commaSep staticVarP
        semi
        pure vars
      where
        staticVarP = do
            var <- variableP
            def <- optional (symbol "=" *> exprP)
            pure (var, def)

    unsetP = do
        reserved "unset"
        exprs <- parens (commaSep exprP)
        semi
        pure exprs

    declareP = do
        reserved "declare"
        directives <- parens (commaSep directiveP)
        body <- braces (many statementP) <|> (semi >> pure ([] :: [Located Statement]))  -- Empty body with just semicolon
        pure (directives, body)
      where
        directiveP = do
            name <- nameP
            _ <- symbol "="
            value <- literalP
            pure (name, value)

    exprStmtP = do
        e <- exprP
        semi
        pure $ StmtExpr e

-- | Pattern match helpers for statement construction
-- | Parse declaration
declarationP :: Parser Declaration
declarationP = choice
    [ functionP
    , classP
    , traitP
    , interfaceP
    , enumP
    ]

-- | Parse attribute (PHP 8.0+)
attributeP :: Parser Attribute
attributeP = do
    _ <- symbol "#["
    name <- qualifiedNameP
    args <- option [] (parens (commaSep argumentP))
    _ <- symbol "]"
    pure Attribute { attrName = name, attrArgs = args }

-- | Parse function
functionP :: Parser Declaration
functionP = do
    attrs <- many attributeP
    reserved "function"
    name <- nameP
    params <- parens (commaSep parameterP)
    ret <- optional returnTypeP
    body <- braces (many statementP)
    pure DeclFunction
        { fnName = name
        , fnParams = params
        , fnReturnType = ret
        , fnBody = body
        , fnAttributes = attrs
        }

-- | Parse class (with PHP 8.2 readonly class support)
classP :: Parser Declaration
classP = do
    attrs <- many attributeP
    -- PHP 8.2: readonly modifier can appear before 'class'
    readonlyClass <- option False (True <$ reserved "readonly")
    mods <- many modifierP
    reserved "class"
    name <- nameP
    ext <- optional (reserved "extends" *> qualifiedNameP)
    impls <- option [] (reserved "implements" *> qualifiedNameP `sepBy1` symbol ",")
    members <- braces (many classMemberP)
    let allMods = if readonlyClass then Readonly : mods else mods
    pure DeclClass
        { clsName = name
        , clsModifiers = allMods
        , clsExtends = ext
        , clsImplements = impls
        , clsMembers = members
        , clsAttributes = attrs
        }

-- | Parse trait (PHP 8.2: supports constants)
traitP :: Parser Declaration
traitP = do
    reserved "trait"
    name <- nameP
    members <- braces (many classMemberP)  -- Reuse classMemberP which handles constants
    pure DeclTrait
        { traitName = name
        , traitMembers = members
        }

-- | Parse interface
interfaceP :: Parser Declaration
interfaceP = do
    reserved "interface"
    name <- nameP
    ext <- option [] (reserved "extends" *> qualifiedNameP `sepBy1` symbol ",")
    methods <- braces (many interfaceMethodP)
    pure DeclInterface
        { ifaceName = name
        , ifaceExtends = ext
        , ifaceMethods = methods
        }
  where
    interfaceMethodP = do
        vis <- option Public visibilityP
        reserved "function"
        name <- nameP
        params <- parens (commaSep parameterP)
        ret <- optional returnTypeP
        semi
        pure InterfaceMethod
            { imethName = name
            , imethParams = params
            , imethReturn = ret
            }

-- | Parse enum (PHP 8.1+)
enumP :: Parser Declaration
enumP = do
    reserved "enum"
    name <- nameP
    backedType <- optional (symbol ":" *> phpTypeP)
    body <- braces $ do
        cases <- many enumCaseP
        methods <- many classMemberP
        pure (cases, methods)
    pure DeclEnum
        { enumName = name
        , enumBackedType = backedType
        , enumCases = fst body
        , enumMethods = snd body
        }
  where
    enumCaseP = do
        reserved "case"
        name <- nameP
        value <- optional (symbol "=" *> literalP)
        semi
        pure EnumCase { ecaseName = name, ecaseValue = value }

-- | Parse modifier
modifierP :: Parser Modifier
modifierP = choice
    [ Static <$ reserved "static"
    , Final <$ reserved "final"
    , Abstract <$ reserved "abstract"
    , Readonly <$ reserved "readonly"
    ]

-- | Parse visibility
visibilityP :: Parser Visibility
visibilityP = choice
    [ Public <$ reserved "public"
    , Protected <$ reserved "protected"
    , Private <$ reserved "private"
    ]

-- | Parse class member
classMemberP :: Parser ClassMember
classMemberP = choice
    [ methodP
    , propertyP
    ]

-- | Parse method
methodP :: Parser ClassMember
methodP = do
    attrs <- many attributeP
    vis <- option Public visibilityP
    mods <- many modifierP
    reserved "function"
    name <- nameP
    params <- parens (commaSep parameterP)
    ret <- optional returnTypeP
    body <- optional (braces (many statementP))
    pure MemberMethod
        { methVisibility = vis
        , methModifiers = mods
        , methName = name
        , methParams = params
        , methReturn = ret
        , methBody = body
        , methAttributes = attrs
        }

-- | Parse property
propertyP :: Parser ClassMember
propertyP = do
    vis <- visibilityP
    mods <- many modifierP
    mType <- optional typeHintP
    name <- variableP
    def <- optional (symbol "=" *> exprP)
    semi
    pure MemberProperty
        { propVisibility = vis
        , propModifiers = mods
        , propType = mType
        , propName = Name (varName name)
        , propDefault = def
        }

-- | Parse parameter (with PHP 8.0 attributes and PHP 8.0 constructor promotion)
parameterP :: Parser Parameter
parameterP = do
    attrs <- many attributeP
    -- Constructor promotion: public/protected/private readonly? Type $var
    vis <- optional visibilityP
    readonly <- option False (True <$ reserved "readonly")
    mType <- optional typeHintP
    byRef <- option False (True <$ symbol "&")
    variadic <- option False (True <$ symbol "...")
    name <- variableP
    def <- optional (symbol "=" *> exprP)
    pure Parameter
        { paramType = mType
        , paramByRef = byRef
        , paramVariadic = variadic
        , paramName = name
        , paramDefault = def
        , paramVisibility = vis
        , paramReadonly = readonly
        , paramAttributes = attrs
        }

-- | Parse type hint
typeHintP :: Parser TypeHint
typeHintP = do
    nullable <- option False (True <$ symbol "?")
    t <- phpTypeP
    pure TypeHint { thType = t, thNullable = nullable }

-- | Parse return type
returnTypeP :: Parser ReturnType
returnTypeP = do
    _ <- symbol ":"
    nullable <- option False (True <$ symbol "?")
    t <- phpTypeP
    pure ReturnType { rtType = t, rtNullable = nullable }

-- | Parse PHP type (with PHP 8.2 DNF types)
phpTypeP :: Parser PhpType
phpTypeP = unionTypeP
  where
    -- Union type: A|B|C or (A&B)|(C&D) [DNF]
    unionTypeP = do
        first <- intersectionTypeP
        rest <- many (symbol "|" *> intersectionTypeP)
        pure $ case rest of
            [] -> first
            _  -> TUnion (first : rest)

    -- Intersection type: A&B&C
    intersectionTypeP = do
        first <- atomicTypeP
        rest <- many (symbol "&" *> atomicTypeP)
        pure $ case rest of
            [] -> first
            _  -> TIntersection (first : rest)

    -- Atomic type or parenthesized intersection (for DNF)
    atomicTypeP = choice
        [ parens intersectionTypeP  -- (A&B) for DNF
        , simpleTypeP
        ]

    -- Simple (non-compound) type
    simpleTypeP = choice
        [ TInt <$ reserved "int"
        , TFloat <$ reserved "float"
        , TString <$ reserved "string"
        , TBool <$ reserved "bool"
        , TArray Nothing <$ reserved "array"
        , TObject Nothing <$ reserved "object"
        , TCallable <$ reserved "callable"
        , TIterable <$ reserved "iterable"
        , TMixed <$ reserved "mixed"
        , TVoid <$ reserved "void"
        , TNever <$ reserved "never"
        , TNull <$ reserved "null"
        , TSelf <$ reserved "self"
        , TStatic <$ reserved "static"
        , TParent <$ reserved "parent"
        , TClass <$> qualifiedNameP
        ]

-- | Parse expression
exprP :: Parser (Located Expr)
exprP = do
    pos <- getSourcePos
    let loc = toSourcePos pos
    expr <- makeExprParser termP operatorTable
    pure $ Located loc (locNode expr)

dummyPos :: SourcePos
dummyPos = SourcePos "" 0 0

locWithDummy :: Expr -> Located Expr
locWithDummy = Located dummyPos

-- | Operator table for expression parser
operatorTable :: [[Operator Parser (Located Expr)]]
operatorTable =
    [ [ prefix "!" (ExprUnary OpNot)
      , prefix "-" (ExprUnary OpNeg)
      , prefix "+" (ExprUnary OpPos)
      , prefix "++" (ExprUnary OpPreInc)
      , prefix "--" (ExprUnary OpPreDec)
      ]
    , [ infixL "**" (ExprBinary OpPow) ]
    , [ infixL "*" (ExprBinary OpMul)
      , infixL "/" (ExprBinary OpDiv)
      , infixL "%" (ExprBinary OpMod)
      ]
    , [ infixL "+" (ExprBinary OpAdd)
      , infixL "-" (ExprBinary OpSub)
      , infixL "." (ExprBinary OpConcat)
      ]
    , [ infixL "<<" (ExprBinary OpShiftL)
      , infixL ">>" (ExprBinary OpShiftR)
      ]
    , [ infixN "<" (ExprBinary OpLt)
      , infixN ">" (ExprBinary OpGt)
      , infixN "<=" (ExprBinary OpLte)
      , infixN ">=" (ExprBinary OpGte)
      ]
    , [ infixN "===" (ExprBinary OpIdentical)
      , infixN "!==" (ExprBinary OpNotIdentical)
      , infixN "==" (ExprBinary OpEq)
      , infixN "!=" (ExprBinary OpNeq)
      ]
    , [ infixL "&" (ExprBinary OpBitAnd) ]
    , [ infixL "^" (ExprBinary OpBitXor) ]
    , [ infixL "|" (ExprBinary OpBitOr) ]
    , [ infixL "&&" (ExprBinary OpAnd) ]
    , [ infixL "||" (ExprBinary OpOr) ]
    , [ Postfix ternaryP ]  -- Ternary operator: expr ? expr : expr
    , [ infixR "??" (ExprBinary OpCoalesce) ]
    , [ infixR "??=" (\l r -> ExprAssignOp OpCoalesce l r)  -- PHP 7.4
      , infixR "+=" (\l r -> ExprAssignOp OpAdd l r)
      , infixR "-=" (\l r -> ExprAssignOp OpSub l r)
      , infixR "*=" (\l r -> ExprAssignOp OpMul l r)
      , infixR "/=" (\l r -> ExprAssignOp OpDiv l r)
      , infixR ".=" (\l r -> ExprAssignOp OpConcat l r)
      , infixR "=" ExprAssign
      ]
    ]
  where
    prefix name f = Prefix ((\e -> locWithDummy (f e)) <$ symbol name)
    infixL name f = InfixL ((\l r -> locWithDummy (f l r)) <$ symbol name)
    infixR name f = InfixR ((\l r -> locWithDummy (f l r)) <$ symbol name)
    infixN name f = InfixN ((\l r -> locWithDummy (f l r)) <$ symbol name)

    -- Ternary operator: cond ? then : else or cond ?: else (elvis)
    ternaryP = do
        _ <- symbol "?"
        thenExpr <- optional exprP  -- Elvis operator allows omitting middle
        _ <- symbol ":"
        elseExpr <- exprP
        pure $ \cond -> locWithDummy (ExprTernary cond thenExpr elseExpr)

-- | Parse a term (base expression)
termP :: Parser (Located Expr)
termP = do
    base <- choice
        [ locWithDummy . ExprLiteral <$> literalP
        , locWithDummy . ExprVariable <$> variableP
        , try newP
        , try callP
        , try arrowFunctionP
        , try closureP
        , locWithDummy . ExprConstant <$> qualifiedNameP
        , parens exprP
        ]
    postfixP base
  where
    -- Handle postfix operations: method calls, property access, array access
    postfixP :: Located Expr -> Parser (Located Expr)
    postfixP base = do
        ops <- many postfixOpP
        pure $ foldl applyPostfix base ops

    postfixOpP = choice
        [ MethodCall <$> (symbol "->" *> nameP) <*> parens (commaSep argumentP)
        , NullsafeMethodCall <$> (symbol "?->" *> nameP) <*> parens (commaSep argumentP)
        , PropertyAccess <$> (symbol "->" *> nameP)
        , NullsafePropertyAccess <$> (symbol "?->" *> nameP)
        , ArrayAccess <$> brackets (optional exprP)
        ]

    applyPostfix base op = case op of
        MethodCall name args -> locWithDummy $ ExprMethodCall base name args
        NullsafeMethodCall name args -> locWithDummy $ ExprNullsafeMethodCall base name args
        PropertyAccess name -> locWithDummy $ ExprPropertyAccess base name
        NullsafePropertyAccess name -> locWithDummy $ ExprNullsafePropertyAccess base name
        ArrayAccess idx -> locWithDummy $ ExprArrayAccess base idx

-- | Postfix operation types
data PostfixOp
    = MethodCall Name [Argument]
    | NullsafeMethodCall Name [Argument]
    | PropertyAccess Name
    | NullsafePropertyAccess Name
    | ArrayAccess (Maybe (Located Expr))

-- | Parse new expression
newP :: Parser (Located Expr)
newP = do
    reserved "new"
    className <- qualifiedNameP
    args <- option [] (parens (commaSep argumentP))
    pure $ locWithDummy $ ExprNew className args

-- | Parse function call
callP :: Parser (Located Expr)
callP = do
    name <- qualifiedNameP
    args <- parens (commaSep argumentP)
    pure $ locWithDummy $ ExprCall (locWithDummy $ ExprConstant name) args

-- | Parse arrow function (PHP 7.4+)
arrowFunctionP :: Parser (Located Expr)
arrowFunctionP = do
    reserved "fn"
    params <- parens (commaSep parameterP)
    ret <- optional returnTypeP
    _ <- symbol "=>"
    expr <- exprP
    pure $ locWithDummy ExprArrowFunction
        { arrowParams = params
        , arrowReturn = ret
        , arrowExpr = expr
        }

-- | Parse closure
closureP :: Parser (Located Expr)
closureP = do
    static <- option False (True <$ reserved "static")
    reserved "function"
    params <- parens (commaSep parameterP)
    uses <- option [] (reserved "use" *> parens (commaSep useVarP))
    ret <- optional returnTypeP
    body <- braces (many statementP)
    pure $ locWithDummy ExprClosure
        { closureStatic = static
        , closureParams = params
        , closureUses = uses
        , closureReturn = ret
        , closureBody = body
        }
  where
    useVarP = do
        byRef <- option False (True <$ symbol "&")
        var <- variableP
        pure (var, byRef)

-- | Parse argument
argumentP :: Parser Argument
argumentP = do
    name <- optional $ try (nameP <* symbol ":")
    unpack <- option False (True <$ symbol "...")
    value <- exprP
    pure Argument
        { argName = name
        , argValue = value
        , argUnpack = unpack
        }

-- | Parse literal
literalP :: Parser Literal
literalP = choice
    [ LitInt <$> lexeme L.decimal
    , LitFloat <$> lexeme L.float
    , LitString <$> stringP
    , LitBool True <$ reserved "true"
    , LitBool False <$ reserved "false"
    , LitNull <$ reserved "null"
    , LitArray <$> arrayP
    ]

-- | Parse string literal
stringP :: Parser Text
stringP = lexeme $ choice
    [ singleQuoted
    , doubleQuoted
    ]
  where
    singleQuoted = char '\'' *> (T.pack <$> manyTill L.charLiteral (char '\''))
    doubleQuoted = char '"' *> (T.pack <$> manyTill L.charLiteral (char '"'))

-- | Parse array literal (with PHP 7.4+ spread operator)
arrayP :: Parser [(Maybe (Located Expr), Located Expr)]
arrayP = brackets (commaSep arrayItemP) <|> (reserved "array" *> parens (commaSep arrayItemP))
  where
    arrayItemP = do
        -- Spread operator: ...$array
        spread <- option False (True <$ symbol "...")
        if spread
            then do
                value <- exprP
                -- Represent spread as special key-value pair
                pure (Nothing, value)  -- Spread items have no key
            else do
                key <- optional $ try (exprP <* symbol "=>")
                value <- exprP
                pure (key, value)

-- | Convert Megaparsec source position to our SourcePos
toSourcePos :: MPPos.SourcePos -> Sanctify.AST.SourcePos
toSourcePos pos = Sanctify.AST.SourcePos
    { posFile = sourceName pos
    , posLine = unPos (sourceLine pos)
    , posColumn = unPos (sourceColumn pos)
    }
