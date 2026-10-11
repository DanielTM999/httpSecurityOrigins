<?php

namespace Daniel\HttpSecurity\Internal;

interface CookieEmitter
{
    public function emit(string $header): void;
}
