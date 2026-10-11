<?php

namespace Daniel\HttpSecurity;

final class PhpSerializedAuthContextCodec implements AuthContextCodec
{
    public function encode(AuthContext $context): string
    {
        return serialize($context);
    }

    public function decode(string $data): AuthContext
    {
        set_error_handler(static function (): never {
            throw new \UnexpectedValueException('Contexto serializado inválido.');
        });
        try {
            $context = unserialize($data);
        } finally {
            restore_error_handler();
        }
        if (!$context instanceof AuthContext) {
            throw new \UnexpectedValueException('Contexto restaurado deve implementar AuthContext.');
        }
        $this->validateGraph($context, new \SplObjectStorage());
        return $context;
    }

    private function validateGraph(mixed $value, \SplObjectStorage $visited): void
    {
        if (is_array($value)) {
            foreach ($value as $item) {
                $this->validateGraph($item, $visited);
            }
            return;
        }
        if (!is_object($value)) {
            return;
        }
        if ($value instanceof \__PHP_Incomplete_Class) {
            throw new \UnexpectedValueException('Classe do contexto de autenticação indisponível.');
        }
        if ($visited->contains($value)) {
            return;
        }
        $visited->attach($value);
        foreach ((array) $value as $item) {
            $this->validateGraph($item, $visited);
        }
    }
}
