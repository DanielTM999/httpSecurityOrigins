<?php

namespace Daniel\HttpSecurity;

final class StatefulStorage
{
    public const SESSION = 'session';
    public const COOKIE = 'cookie';

    public static function validate(string $storage): string
    {
        if (!in_array($storage, [self::SESSION, self::COOKIE], true)) {
            throw new \InvalidArgumentException('Armazenamento deve ser session ou cookie.');
        }
        return $storage;
    }
}
