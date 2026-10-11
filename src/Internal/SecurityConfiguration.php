<?php

namespace Daniel\HttpSecurity\Internal;

use Daniel\HttpSecurity\AuthContextCodec;
use Daniel\HttpSecurity\CookieOptions;
use Daniel\HttpSecurity\PhpSerializedAuthContextCodec;
use Daniel\HttpSecurity\SessionPolice;
use Daniel\HttpSecurity\StatefulStorage;

final class SecurityConfiguration
{
    private static int $police = SessionPolice::STATELESS;
    private static ?string $storage = null;
    private static ?CookieOptions $cookieOptions = null;
    private static ?AuthContextCodec $codec = null;
    private static ?AuthContextCodec $defaultCodec = null;
    private static ?CookieEmitter $emitter = null;

    private function __construct()
    {
    }

    public static function setPolice(int $police): void
    {
        if (!in_array($police, [SessionPolice::STATEFULL, SessionPolice::STATELESS], true)) {
            throw new \InvalidArgumentException('Política de sessão deve ser SessionPolice::STATEFULL ou SessionPolice::STATELESS.');
        }
        self::$police = $police;
        ContextPersistence::invalidate();
    }

    public static function police(): int
    {
        return self::$police;
    }

    public static function isStateful(): bool
    {
        return self::$police === SessionPolice::STATEFULL;
    }

    public static function setStorage(string $storage): void
    {
        self::$storage = StatefulStorage::validate($storage);
        ContextPersistence::invalidate();
    }

    public static function storage(): string
    {
        if (self::$storage !== null) {
            return self::$storage;
        }
        $value = $_ENV['HTTP_SECURITY_STATEFUL_STORAGE'] ?? StatefulStorage::SESSION;
        if (!is_string($value)) {
            throw new \InvalidArgumentException('HTTP_SECURITY_STATEFUL_STORAGE deve ser session ou cookie.');
        }
        return StatefulStorage::validate(strtolower(trim($value)));
    }

    public static function usesCookie(): bool
    {
        return self::isStateful() && self::storage() === StatefulStorage::COOKIE;
    }

    public static function setCookieOptions(CookieOptions $options): void
    {
        self::$cookieOptions = $options;
        ContextPersistence::invalidate();
    }

    public static function cookieOptions(): CookieOptions
    {
        return self::$cookieOptions ?? new CookieOptions();
    }

    public static function setCodec(AuthContextCodec $codec): void
    {
        self::$codec = $codec;
        ContextPersistence::invalidate();
    }

    public static function codec(): AuthContextCodec
    {
        return self::$codec ?? (self::$defaultCodec ??= new PhpSerializedAuthContextCodec());
    }

    public static function setEmitter(?CookieEmitter $emitter): void
    {
        self::$emitter = $emitter;
        ContextPersistence::invalidate();
    }

    public static function cookieStorage(): CookieContextStorage
    {
        $options = self::cookieOptions()->resolve();
        return new CookieContextStorage(
            $options,
            $options->encryptionKey(),
            self::$emitter ?? new NativeCookieEmitter()
        );
    }

    public static function reset(): void
    {
        self::$police = SessionPolice::STATELESS;
        self::$storage = null;
        self::$cookieOptions = null;
        self::$codec = null;
        self::$emitter = null;
        ContextPersistence::reset();
    }
}
