<?php

namespace Daniel\HttpSecurity\Internal;

final class NativeCookieEmitter implements CookieEmitter
{
    public function emit(string $header): void
    {
        if (headers_sent()) {
            throw new \RuntimeException('Não foi possível emitir o cookie de autenticação: cabeçalhos já enviados.');
        }
        set_error_handler(static function (): never {
            throw new \RuntimeException('Falha na emissão do cookie de autenticação.');
        });
        try {
            header($header, false);
        } finally {
            restore_error_handler();
        }
    }
}
