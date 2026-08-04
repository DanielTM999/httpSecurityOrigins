<?php

namespace Daniel\HttpSecurity;

use Exception;

class EnvironmentAuthorizationException extends Exception
{
    private string $getUserEnv;
    private string $getTargetEnv;

    public function __construct(
        $message = 'Authorization Environment error',
        $code = 0,
        string $getUserEnv,
        string $gettargetEnv,
        Exception|null $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->getUserEnv = $getUserEnv;
        $this->getTargetEnv = $gettargetEnv;
    }

    public function getUserEnvaroment(): string
    {
        return $this->getUserEnv;
    }

    public function getTargetEnvaroment(): string
    {
        return $this->getTargetEnv;
    }
}

