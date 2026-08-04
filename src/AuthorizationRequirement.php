<?php

namespace Daniel\HttpSecurity;

use InvalidArgumentException;

final class AuthorizationRequirement
{
    private function __construct(
        private array $roles,
        private ?AuthorizationValidator $validator
    ) {
    }

    public static function from(array|string|AuthorizationValidator $authorization = []): self
    {
        if ($authorization instanceof AuthorizationValidator) {
            return new self([], $authorization);
        }

        $roles = is_string($authorization) ? [$authorization] : $authorization;
        foreach ($roles as $role) {
            if (!is_string($role)) {
                throw new InvalidArgumentException(
                    'As roles devem ser strings ou um AuthorizationValidator deve ser informado.'
                );
            }
        }

        return new self(array_values($roles), null);
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function getValidator(): ?AuthorizationValidator
    {
        return $this->validator;
    }
}

