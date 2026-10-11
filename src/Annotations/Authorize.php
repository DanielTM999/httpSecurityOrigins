<?php

namespace Daniel\HttpSecurity\Annotations;

use Attribute;
use Daniel\HttpSecurity\AuthorizationValidator;

#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
class Authorize
{
    public function __construct(
        public array|string|AuthorizationValidator $authorization = []
    ) {}
}

