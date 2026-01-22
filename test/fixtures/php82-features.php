<?php
// SPDX-License-Identifier: PMPL-1.0-or-later
// Test fixture: PHP 8.2+ features

declare(strict_types=1);

// Readonly classes
readonly class UserDTO {
    public function __construct(
        public string $name,
        public string $email,
        public int $age
    ) {}
}

// DNF types (Disjunctive Normal Form)
function processInput((Stringable&Countable)|(ArrayAccess&Traversable) $data): void {
    // Process the data
}

// Enums with backed values
enum Status: string {
    case Pending = 'pending';
    case Approved = 'approved';
    case Rejected = 'rejected';

    public function getLabel(): string {
        return match($this) {
            self::Pending => 'Pending Review',
            self::Approved => 'Approved',
            self::Rejected => 'Rejected',
        };
    }
}

// Attributes on all declarations
#[Route('/api/users')]
#[Middleware('auth')]
class UserController {
    #[Get('/list')]
    #[Cache(ttl: 3600)]
    public function list(): array {
        return [];
    }

    #[Post('/create')]
    #[Validate(['email' => 'required|email'])]
    public function create(#[FromBody] array $data): UserDTO {
        return new UserDTO(
            name: $data['name'],
            email: $data['email'],
            age: $data['age']
        );
    }
}

// Trait constants (PHP 8.2)
trait LoggingTrait {
    public const LOG_LEVEL = 'debug';
    private const MAX_ENTRIES = 1000;

    protected function log(string $message): void {
        error_log(self::LOG_LEVEL . ': ' . $message);
    }
}

// Match expressions
function getHttpStatusMessage(int $code): string {
    return match($code) {
        200 => 'OK',
        201 => 'Created',
        400 => 'Bad Request',
        401 => 'Unauthorized',
        403 => 'Forbidden',
        404 => 'Not Found',
        500 => 'Internal Server Error',
        default => 'Unknown Status'
    };
}

// Arrow functions
$multiply = fn(int $x, int $y): int => $x * $y;
$filter = fn(array $items): array => array_filter($items, fn($item) => $item > 0);

// Null coalescing assignment
function ensureConfig(array &$config): void {
    $config['timeout'] ??= 30;
    $config['retries'] ??= 3;
    $config['cache'] ??= true;
}

// Nullsafe operator
function getUserEmail(?User $user): ?string {
    return $user?->profile?->email;
}
