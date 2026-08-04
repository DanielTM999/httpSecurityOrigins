<?php

namespace Daniel\HttpSecurity\Annotations;

use Attribute;

/** Alias em português mantido para a API solicitada. */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final class Autorize extends Authorize
{
}

