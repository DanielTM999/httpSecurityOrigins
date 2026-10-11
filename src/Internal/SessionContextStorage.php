<?php

namespace Daniel\HttpSecurity\Internal;

final class SessionContextStorage implements ContextStorage
{
    public const KEY = 'Securitycontext';

    public function load(): ?string
    {
        $data = $_SESSION[self::KEY] ?? null;
        if ($data !== null && !is_string($data)) {
            throw new \UnexpectedValueException('Contexto de sessão inválido.');
        }
        return $data;
    }

    public function save(string $data): void
    {
        $_SESSION[self::KEY] = $data;
    }

    public function clear(): void
    {
        unset($_SESSION[self::KEY]);
    }
}
