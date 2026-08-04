<?php

namespace Daniel\HttpSecurity;

use Exception;

class AuthorityAuthorizationException extends Exception
{
    public function __construct($message = 'Authorization Roles error', $code = 0, Exception|null $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}

