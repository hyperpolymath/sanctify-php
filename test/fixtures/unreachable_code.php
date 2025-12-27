<?php
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: Unreachable code test case

declare(strict_types=1);

function testReturn(): int
{
    $x = 10;
    return $x;
    $y = 20;  // Unreachable - after return
    echo $y;  // Unreachable - after return
}

function testThrow(): void
{
    throw new Exception("error");
    $cleanup = true;  // Unreachable - after throw
}

function testConditionalReturn(bool $flag): int
{
    if ($flag) {
        return 1;
        $dead = "never";  // Unreachable within if block
    }
    return 0;  // This IS reachable (not in the if block)
}

function testBreakInLoop(): void
{
    for ($i = 0; $i < 10; $i++) {
        if ($i === 5) {
            break;
            $afterBreak = $i;  // Unreachable - after break
        }
        echo $i;  // Reachable - outside the if with break
    }
}

function testContinueInLoop(): void
{
    foreach ([1, 2, 3] as $val) {
        if ($val === 2) {
            continue;
            $afterContinue = $val;  // Unreachable - after continue
        }
        process($val);  // Reachable
    }
}
