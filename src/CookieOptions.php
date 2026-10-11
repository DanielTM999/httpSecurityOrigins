<?php

namespace Daniel\HttpSecurity;

final class CookieOptions
{
    public function __construct(
        public readonly ?string $name = null,
        public readonly ?int $ttl = null,
        #[\SensitiveParameter] public readonly ?string $key = null,
        public readonly ?string $path = null,
        public readonly ?string $domain = null,
        public readonly ?bool $secure = null,
        public readonly ?string $sameSite = null
    ) {
    }

    public function resolve(): self
    {
        $name = $this->name ?? self::env('NAME', 'http_security_context');
        $ttl = $this->ttl ?? self::integer(self::env('TTL', '2592000'));
        $key = $this->key ?? self::env('KEY', '');
        $path = $this->path ?? self::env('PATH', '/');
        $domain = $this->domain ?? self::env('DOMAIN', '');
        $secure = $this->secure ?? self::boolean(self::env('SECURE', 'true'));
        $sameSite = $this->sameSite ?? self::env('SAME_SITE', 'Lax');

        if (!preg_match('/\A[A-Za-z_][A-Za-z0-9_-]*\z/D', $name)) {
            throw new \InvalidArgumentException('Nome de cookie inválido.');
        }
        if ($ttl <= 0 || $ttl > PHP_INT_MAX - time()) {
            throw new \InvalidArgumentException('TTL do cookie deve ser inteiro positivo sem overflow.');
        }
        if (!str_starts_with($path, '/') || preg_match('/[^\x21-\x7e]|[;,]/', $path)) {
            throw new \InvalidArgumentException('Path do cookie deve começar com / e não conter separadores ou controles.');
        }
        if ($domain !== '' && !preg_match('/\A\.?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\z/iD', $domain)) {
            throw new \InvalidArgumentException('Domain do cookie inválido.');
        }
        if (!in_array($sameSite, ['Lax', 'Strict', 'None'], true) || ($sameSite === 'None' && !$secure)) {
            throw new \InvalidArgumentException('SameSite deve ser Lax, Strict ou None; None exige Secure.');
        }
        return new self($name, $ttl, $key, $path, $domain, $secure, $sameSite);
    }

    public function encryptionKey(): string
    {
        $key = base64_decode($this->key ?? '', true);
        if ($key === false || strlen($key) !== 32 || base64_encode($key) !== $this->key) {
            throw new \InvalidArgumentException('HTTP_SECURITY_COOKIE_KEY deve ser base64 canônica de exatamente 32 bytes.');
        }
        if (!extension_loaded('openssl') || !in_array('aes-256-gcm', openssl_get_cipher_methods(), true)) {
            throw new \RuntimeException('Persistência por cookie exige OpenSSL com AES-256-GCM.');
        }
        return $key;
    }

    public function header(string $value, int $expiresAt, int $now): string
    {
        $header = 'Set-Cookie: ' . $this->name . '=' . rawurlencode($value)
            . '; Expires=' . gmdate('D, d M Y H:i:s \G\M\T', $expiresAt)
            . '; Max-Age=' . max(0, $expiresAt - $now)
            . '; Path=' . $this->path;
        if ($this->domain !== '') {
            $header .= '; Domain=' . $this->domain;
        }
        if ($this->secure) {
            $header .= '; Secure';
        }
        return $header . '; HttpOnly; SameSite=' . $this->sameSite;
    }

    private static function env(string $suffix, string $default): string
    {
        $value = $_ENV['HTTP_SECURITY_COOKIE_' . $suffix] ?? $default;
        if (!is_string($value)) {
            throw new \InvalidArgumentException('Opções de ambiente do cookie devem ser strings.');
        }
        return $value;
    }

    private static function integer(string $value): int
    {
        if (!preg_match('/\A[0-9]+\z/D', $value)
            || filter_var($value, FILTER_VALIDATE_INT) === false) {
            throw new \InvalidArgumentException('HTTP_SECURITY_COOKIE_TTL deve ser inteiro positivo.');
        }
        return (int) $value;
    }

    private static function boolean(string $value): bool
    {
        return match (strtolower($value)) {
            'true', '1' => true,
            'false', '0' => false,
            default => throw new \InvalidArgumentException('HTTP_SECURITY_COOKIE_SECURE deve ser true, false, 1 ou 0.'),
        };
    }
}
