<?php
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: Unused function parameters test case

declare(strict_types=1);

// Case 1: Unused parameter
function greet(string $name, int $age): string  // $age is unused
{
    return "Hello, " . $name;
}

// Case 2: All parameters used
function add(int $a, int $b): int
{
    return $a + $b;
}

// Case 3: Multiple unused parameters
function complex(string $x, int $y, bool $z): void  // $y and $z unused
{
    echo $x;
}

// Case 4: Unused parameter in class method
class Calculator
{
    public function multiply(int $a, int $b, int $precision): int  // $precision unused
    {
        return $a * $b;
    }

    public function divide(float $numerator, float $denominator): float
    {
        return $numerator / $denominator;  // Both used
    }
}

// Case 5: Callback with unused parameters (common pattern)
$callback = function (array $items, int $index): mixed {  // $index unused
    return $items[0];
};
