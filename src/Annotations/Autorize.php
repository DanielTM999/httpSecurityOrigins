<?php

namespace Daniel\HttpSecurity\Annotations;

use Attribute;


#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final class Autorize extends Authorize
{
}

