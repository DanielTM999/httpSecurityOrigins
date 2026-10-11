<?php

namespace Daniel\HttpSecurity\Internal;

use Daniel\HttpSecurity\CookieOptions;

final class CookieContextStorage implements ContextStorage
{
    public const MAX_HEADER_BYTES = 4096;
    private const VERSION = 1;
    private const PREFIX = 'v1.';
    private const IV_BYTES = 12;
    private const TAG_BYTES = 16;

    public function __construct(
        private readonly CookieOptions $options,
        #[\SensitiveParameter] private readonly string $key,
        private readonly CookieEmitter $emitter
    ) {
    }

    public function hasCookie(): bool
    {
        return array_key_exists($this->options->name, $_COOKIE ?? []);
    }

    public function load(): ?string
    {
        if (!$this->hasCookie()) {
            return null;
        }
        $value = $_COOKIE[$this->options->name];
        if (!is_string($value) || strlen($value) > self::MAX_HEADER_BYTES || !str_starts_with($value, self::PREFIX)) {
            throw new \UnexpectedValueException('Formato de cookie inválido.');
        }
        $raw = substr($value, strlen(self::PREFIX));
        if (!preg_match('/\A[A-Za-z0-9_-]+\z/D', $raw)) {
            throw new \UnexpectedValueException('Codificação do cookie inválida.');
        }
        $binary = base64_decode(strtr($raw, '-_', '+/'), true);
        if ($binary === false || strlen($binary) <= self::IV_BYTES + self::TAG_BYTES || self::base64url($binary) !== $raw) {
            throw new \UnexpectedValueException('Comprimento do cookie inválido.');
        }
        $plaintext = openssl_decrypt(
            substr($binary, self::IV_BYTES + self::TAG_BYTES),
            'aes-256-gcm',
            $this->key,
            OPENSSL_RAW_DATA,
            substr($binary, 0, self::IV_BYTES),
            substr($binary, self::IV_BYTES, self::TAG_BYTES),
            $this->aad()
        );
        if ($plaintext === false) {
            throw new \UnexpectedValueException('Autenticação do cookie inválida.');
        }
        $envelope = json_decode($plaintext, true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($envelope)
            || ($envelope['version'] ?? null) !== self::VERSION
            || !is_int($envelope['issuedAt'] ?? null)
            || !is_int($envelope['expiresAt'] ?? null)
            || !is_string($envelope['context'] ?? null)
            || $envelope['issuedAt'] < 0
            || $envelope['expiresAt'] <= $envelope['issuedAt']) {
            throw new \UnexpectedValueException('Envelope do cookie inválido.');
        }
        if (time() >= $envelope['expiresAt']) {
            throw new \UnexpectedValueException('Cookie de autenticação expirado.');
        }
        $data = base64_decode($envelope['context'], true);
        if ($data === false || base64_encode($data) !== $envelope['context']) {
            throw new \UnexpectedValueException('Representação do contexto inválida.');
        }
        return $data;
    }

    public function save(string $data): void
    {
        $now = time();
        $expiresAt = $now + $this->options->ttl;
        $plaintext = json_encode([
            'version' => self::VERSION,
            'issuedAt' => $now,
            'expiresAt' => $expiresAt,
            'context' => base64_encode($data),
        ], JSON_THROW_ON_ERROR);
        $iv = random_bytes(self::IV_BYTES);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $this->aad(),
            self::TAG_BYTES
        );
        if ($ciphertext === false || strlen($tag) !== self::TAG_BYTES) {
            throw new \RuntimeException('Falha ao proteger o contexto de autenticação.');
        }
        $value = self::PREFIX . self::base64url($iv . $tag . $ciphertext);
        $header = $this->options->header($value, $expiresAt, $now);
        if (strlen($header) > self::MAX_HEADER_BYTES) {
            throw new \LengthException('Contexto excede o limite de 4096 bytes do cabeçalho Set-Cookie; use um codec menor.');
        }
        $this->emitter->emit($header);
        $_COOKIE[$this->options->name] = $value;
    }

    public function clear(): void
    {
        unset($_COOKIE[$this->options->name]);
        $header = $this->options->header('', 1, time());
        if (strlen($header) > self::MAX_HEADER_BYTES) {
            throw new \LengthException('Atributos excedem o limite de 4096 bytes do cabeçalho Set-Cookie.');
        }
        $this->emitter->emit($header);
    }

    private function aad(): string
    {
        return json_encode(
            [self::PREFIX, $this->options->name, $this->options->path, $this->options->domain],
            JSON_THROW_ON_ERROR
        );
    }

    private static function base64url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
