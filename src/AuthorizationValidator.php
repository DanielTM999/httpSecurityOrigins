<?php

namespace Daniel\HttpSecurity;

abstract class AuthorizationValidator
{
    private array $paramArgs;
    private string $message;

    public function __construct(
        array $paramArgs = [],
        string $message = "not authorized [custom validator denied]"
    ) {
        $this->paramArgs = $paramArgs;
        $this->message = $message;
    }

    abstract public function isValid(AuthContext $context): bool;

    public function getParamArgs(): array
    {
        return $this->paramArgs;
    }

    public function setParamArgs(array $paramArgs): self
    {
        $this->paramArgs = $paramArgs;
        return $this;
    }

    public function getMessage(): string
    {
        return $this->message;
    }
}

