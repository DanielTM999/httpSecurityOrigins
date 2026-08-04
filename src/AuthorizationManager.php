<?php

namespace Daniel\HttpSecurity;

final class AuthorizationManager
{
    private function __construct()
    {
    }

    public static function authorize(array|string|AuthorizationValidator $authorization = []): void
    {
        $context = SecurityContext::getContext();
        if ($context === null) {
            throw new AuthorizationException('not authorized');
        }

        $requirement = AuthorizationRequirement::from($authorization);
        self::validate(
            $context,
            $requirement->getRoles(),
            $requirement->getValidator()
        );
    }

    public static function validate(
        AuthContext $context,
        array $roles = [],
        ?AuthorizationValidator $validator = null
    ): void {
        if ($validator !== null && !$validator->isValid($context)) {
            throw new AuthorityAuthorizationException($validator->getMessage());
        }
        if (!empty($roles) && empty(array_intersect($roles, $context->getRoles()))) {
            throw new AuthorityAuthorizationException(
                'not authorized [not conteins permission Role]'
            );
        }
    }
}

