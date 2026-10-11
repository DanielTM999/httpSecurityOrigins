<?php

require dirname(__DIR__) . '/vendor/autoload.php';
require_once dirname(__DIR__) . '/src/HttpSecurityConfigurar.php';

use Daniel\HttpSecurity\Annotations\Autorize;
use Daniel\HttpSecurity\Annotations\Authorize;
use Daniel\HttpSecurity\AuthContext;
use Daniel\HttpSecurity\AuthorizationManager;
use Daniel\HttpSecurity\AuthorityAuthorizationException;
use Daniel\HttpSecurity\AuthorizationValidator;
use Daniel\HttpSecurity\AuthorizeAspect;
use Daniel\HttpSecurity\SecurityContext;

final class TestAuthContext implements AuthContext
{
    public function __construct(private array $authorities) {}
    public function getUser(): string { return 'user'; }
    public function getPassword(): string { return 'password'; }
    public function getRoles(): array { return $this->authorities; }
    public function getEnvironment(): string { return 'test'; }
    public function getUserArgs(): array { return []; }
}

final class ExactAuthorityValidator extends AuthorizationValidator
{
    public function __construct(private string $authority)
    {
        parent::__construct([$authority], "missing $authority");
    }

    public function isValid(AuthContext $context): bool
    {
        return in_array($this->authority, $context->getRoles(), true);
    }
}

#[Autorize('class.access')]
final class SecuredController
{
    public function byClass(): string { return 'class'; }

    #[Authorize(['report.one', 'report.two'])]
    public function byArray(): string { return 'array'; }

    #[Autorize(new ExactAuthorityValidator('custom.access'))]
    public function byValidator(): string { return 'validator'; }
}

function ensure(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function executeAspect(string $methodName): void
{
    $controller = new SecuredController();
    $method = new ReflectionMethod($controller, $methodName);
    $args = [];
    $aspect = new AuthorizeAspect();
    ensure($aspect->pointCut($controller, $method, $args), "pointcut ausente em $methodName");
    $aspect->aspectBefore($controller, $method, $args);
}

$_SESSION = [];

SecurityContext::setContext(new TestAuthContext(['class.access']));
executeAspect('byClass');

SecurityContext::setContext(new TestAuthContext(['report.two']));
executeAspect('byArray');

SecurityContext::setContext(new TestAuthContext(['custom.access']));
executeAspect('byValidator');

SecurityContext::setContext(new TestAuthContext(['direct.access']));
AuthorizationManager::authorize('direct.access');

$denied = false;
try {
    AuthorizationManager::authorize('missing.access');
} catch (AuthorityAuthorizationException) {
    $denied = true;
}
ensure($denied, 'autoridade ausente deveria negar');

SecurityContext::setContext(new TestAuthContext(['class.access']));
$denied = false;
try {
    executeAspect('byArray');
} catch (AuthorityAuthorizationException) {
    $denied = true;
}
ensure($denied, 'a regra do método deveria substituir a regra da classe');

echo "authorize-annotation-test: OK\n";
