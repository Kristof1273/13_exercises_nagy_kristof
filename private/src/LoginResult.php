<?php

declare(strict_types=1);

/**
 * Outcome of Auth::attempt().
 */
final class LoginResult
{
    private function __construct(
        public readonly bool $success,
        public readonly int $retryAfter = 0,
    ) {
    }

    public static function success(): self
    {
        return new self(true);
    }

    public static function failed(): self
    {
        return new self(false);
    }

    public static function blocked(int $retryAfter): self
    {
        return new self(false, $retryAfter);
    }

    public function isBlocked(): bool
    {
        return $this->retryAfter > 0;
    }
}
