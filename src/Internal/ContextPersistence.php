<?php

namespace Daniel\HttpSecurity\Internal;

use Daniel\HttpSecurity\AuthContext;

final class ContextPersistence
{
    private static ?AuthContext $memory = null;
    private static ?AuthContext $cached = null;
    private static bool $resolved = false;
    private static ?CookieContextStorage $cookie = null;

    private function __construct()
    {
    }

    public static function get(): ?AuthContext
    {
        if (!SecurityConfiguration::isStateful()) {
            return self::$memory;
        }
        if (!self::$resolved) {
            self::$cached = self::restore();
            self::$resolved = true;
        }
        return self::$cached;
    }

    public static function set(AuthContext $context): void
    {
        if (!SecurityConfiguration::isStateful()) {
            self::$memory = $context;
            return;
        }
        $data = self::encode($context);
        if (SecurityConfiguration::usesCookie()) {
            self::cookie()->save($data);
            self::session()->clear();
        } else {
            self::session()->save($data);
        }
        self::$cached = $context;
        self::$resolved = true;
    }

    public static function clear(): void
    {
        self::$memory = null;
        self::$cached = null;
        self::$resolved = true;
        self::session()->clear();
        if (SecurityConfiguration::usesCookie()) {
            self::cookie()->clear();
        }
    }

    public static function invalidate(): void
    {
        self::$cached = null;
        self::$resolved = false;
        self::$cookie = null;
    }

    public static function reset(): void
    {
        self::$memory = null;
        self::invalidate();
    }

    private static function restore(): ?AuthContext
    {
        $session = self::session();
        if (!SecurityConfiguration::usesCookie()) {
            return self::restoreSession($session);
        }

        $cookie = self::cookie();
        if ($cookie->hasCookie()) {
            try {
                return self::decode($cookie->load());
            } catch (\Throwable) {
                self::discardCookie($cookie);
                return null;
            }
        }

        $context = self::restoreSession($session);
        if ($context !== null) {
            try {
                $cookie->save(self::encode($context));
                $session->clear();
            } catch (\Throwable) {
            }
        }
        return $context;
    }

    private static function restoreSession(SessionContextStorage $session): ?AuthContext
    {
        try {
            $data = $session->load();
            return $data === null ? null : self::decode($data);
        } catch (\Throwable) {
            $session->clear();
            return null;
        }
    }

    private static function discardCookie(CookieContextStorage $cookie): void
    {
        try {
            $cookie->clear();
        } catch (\Throwable) {
        }
    }

    private static function encode(AuthContext $context): string
    {
        try {
            return SecurityConfiguration::codec()->encode($context);
        } catch (\Throwable $e) {
            throw new \RuntimeException('Falha ao codificar o contexto de autenticação.', 0, $e);
        }
    }

    private static function decode(string $data): AuthContext
    {
        return SecurityConfiguration::codec()->decode($data);
    }

    private static function session(): SessionContextStorage
    {
        return new SessionContextStorage();
    }

    private static function cookie(): CookieContextStorage
    {
        return self::$cookie ??= SecurityConfiguration::cookieStorage();
    }
}
