<?php
// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixture: Clean code with no dead code issues

declare(strict_types=1);

namespace App\Services;

/**
 * A clean service class with no dead code
 */
class UserService
{
    private array $users = [];

    public function __construct()
    {
        $this->users = [];
    }

    public function addUser(string $name, string $email): int
    {
        $id = count($this->users) + 1;
        $this->users[$id] = [
            'name' => $name,
            'email' => $email,
        ];
        return $id;
    }

    public function getUser(int $id): ?array
    {
        if (isset($this->users[$id])) {
            return $this->users[$id];
        }
        return null;
    }

    public function listUsers(): array
    {
        $result = [];
        foreach ($this->users as $id => $user) {
            $result[] = [
                'id' => $id,
                'name' => $user['name'],
            ];
        }
        return $result;
    }
}

// Function with all parameters used
function formatUser(array $user, string $format): string
{
    $name = $user['name'];
    $email = $user['email'];

    if ($format === 'full') {
        return $name . ' <' . $email . '>';
    }
    return $name;
}
