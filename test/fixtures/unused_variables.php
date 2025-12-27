<?php
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: Unused variables test case

declare(strict_types=1);

// Case 1: Simple unused variable
$unusedVar = 42;  // Should be flagged

// Case 2: Used variable - should NOT be flagged
$usedVar = "hello";
echo $usedVar;

// Case 3: Variable assigned but only reassigned, never read
$reassigned = 1;  // Should be flagged
$reassigned = 2;  // This is also unused

// Case 4: Variable used in expression
$a = 10;
$b = 20;
$c = $a + $b;  // $a and $b are used, $c is unused (should be flagged)

// Case 5: Variable used in function call
$message = "test";
strlen($message);  // $message is used

// Case 6: Unused in conditional
if (true) {
    $inCondition = 100;  // Should be flagged as unused
}
