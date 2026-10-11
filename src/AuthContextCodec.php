<?php

namespace Daniel\HttpSecurity;

interface AuthContextCodec
{
    public function encode(AuthContext $context): string;
    public function decode(string $data): AuthContext;
}
