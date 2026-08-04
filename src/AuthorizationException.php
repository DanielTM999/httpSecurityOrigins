<?php

namespace Daniel\HttpSecurity;

use Exception;

class AuthorizationException extends Exception
{
    public function __construct($message = 'Authorization error', $code = 0, Exception|null $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}

