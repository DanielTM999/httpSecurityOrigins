<?php

namespace Daniel\HttpSecurity;

use Daniel\HttpSecurity\Annotations\Autorize;
use Daniel\HttpSecurity\Annotations\Authorize;
use Daniel\Origins\Annotations\FilterPriority;
use Daniel\Origins\AnnotationsUtils;
use Daniel\Origins\Aop\Aspect;
use Override;
use ReflectionClass;
use ReflectionMethod;

#[FilterPriority(PHP_INT_MAX)]
final class AuthorizeAspect extends Aspect
{
    #[Override]
    public function pointCut(object &$controllerEntity, ReflectionMethod &$method, array &$varArgs): bool
    {
        return $this->findAuthorize($method) !== null;
    }

    #[Override]
    public function aspectBefore(object &$controllerEntity, ReflectionMethod &$method, array &$varArgs): void
    {
        $authorize = $this->findAuthorize($method);
        if ($authorize !== null) {
            AuthorizationManager::authorize($authorize->authorization);
        }
    }

    #[Override]
    public function aspectAfter(
        object &$controllerEntity,
        ReflectionMethod &$method,
        array &$varArgs,
        mixed &$result
    ): mixed {
        return $result;
    }

    private function findAuthorize(ReflectionMethod $method): ?Authorize
    {
        $methodAuthorize = $this->getAuthorizeInstance($method);
        if ($methodAuthorize !== null) {
            return $methodAuthorize;
        }

        return $this->getAuthorizeInstance($method->getDeclaringClass());
    }

    private function getAuthorizeInstance(ReflectionMethod|ReflectionClass $target): ?Authorize
    {
        foreach ([Autorize::class, Authorize::class] as $annotation) {
            if (AnnotationsUtils::isAnnotationPresent($target, $annotation)) {
                return AnnotationsUtils::getAnnotationInstance($target, $annotation);
            }
        }
        return null;
    }
}

