<?php

require dirname(__DIR__) . '/vendor/autoload.php';
require_once dirname(__DIR__) . '/src/HttpSecurityConfigurar.php';
require_once dirname(__DIR__) . '/src/SercurityFilterChain.php';

use Daniel\HttpSecurity\Annotations\Authorize;
use Daniel\HttpSecurity\AuthContext;
use Daniel\HttpSecurity\AuthContextCodec;
use Daniel\HttpSecurity\AuthorityAuthorizationException;
use Daniel\HttpSecurity\AuthorizationException;
use Daniel\HttpSecurity\AuthorizationValidator;
use Daniel\HttpSecurity\AuthorizeAspect;
use Daniel\HttpSecurity\CookieOptions;
use Daniel\HttpSecurity\EnvironmentAuthorizationException;
use Daniel\HttpSecurity\HttpSecurityConfigurar;
use Daniel\HttpSecurity\HttpSecurityMiddleware;
use Daniel\HttpSecurity\Internal\CookieEmitter;
use Daniel\HttpSecurity\Internal\NativeCookieEmitter;
use Daniel\HttpSecurity\Internal\SecurityConfiguration;
use Daniel\HttpSecurity\PhpSerializedAuthContextCodec;
use Daniel\HttpSecurity\RequestMatcherAction;
use Daniel\HttpSecurity\SecurityContext;
use Daniel\HttpSecurity\SecurityFilterChain;
use Daniel\HttpSecurity\SessionPolice;
use Daniel\HttpSecurity\StatefulStorage;
use Daniel\Origins\Request;
use Daniel\Origins\Router;

class SimpleContext implements AuthContext
{
    public function __construct(
        public string $user = 'ana',
        public array $roles = ['adm'],
        public string $environment = 'prod'
    ) {
    }

    public function getUser(): string { return $this->user; }
    public function getPassword(): string { return ''; }
    public function getRoles(): array { return $this->roles; }
    public function getEnvironment(): string { return $this->environment; }
    public function getUserArgs(): array { return []; }
}

final class RichContext implements AuthContext
{
    public array $extra = [];

    public function __construct(
        private readonly string $user,
        private readonly array $roles,
        private readonly \DateTimeImmutable $expiresAt,
        private \DateTime $loggedAt,
        private ?SimpleContext $nested = null
    ) {
    }

    public function getUser(): string { return $this->user; }
    public function getPassword(): string { return 'secret'; }
    public function getRoles(): array { return $this->roles; }
    public function getEnvironment(): string { return 'prod'; }
    public function getUserArgs(): array { return ['nested' => $this->nested]; }
    public function getExpiresAt(): \DateTimeImmutable { return $this->expiresAt; }
    public function getLoggedAt(): \DateTime { return $this->loggedAt; }
}

final class JsonContextCodec implements AuthContextCodec
{
    public int $encodes = 0;
    public int $decodes = 0;

    public function encode(AuthContext $context): string
    {
        $this->encodes++;
        return json_encode([
            'user' => $context->getUser(),
            'roles' => $context->getRoles(),
            'environment' => $context->getEnvironment(),
        ], JSON_THROW_ON_ERROR);
    }

    public function decode(string $data): AuthContext
    {
        $this->decodes++;
        $value = json_decode($data, true, 8, JSON_THROW_ON_ERROR);
        return new SimpleContext($value['user'], $value['roles'], $value['environment']);
    }
}

final class LegacyAwareJsonCodec implements AuthContextCodec
{
    private JsonContextCodec $json;
    private PhpSerializedAuthContextCodec $legacy;

    public function __construct()
    {
        $this->json = new JsonContextCodec();
        $this->legacy = new PhpSerializedAuthContextCodec();
    }

    public function encode(AuthContext $context): string
    {
        return $this->json->encode($context);
    }

    public function decode(string $data): AuthContext
    {
        return str_starts_with($data, '{') ? $this->json->decode($data) : $this->legacy->decode($data);
    }
}

final class SpyCodec implements AuthContextCodec
{
    public array $decoded = [];
    public int $encodes = 0;
    private PhpSerializedAuthContextCodec $inner;

    public function __construct()
    {
        $this->inner = new PhpSerializedAuthContextCodec();
    }

    public function encode(AuthContext $context): string
    {
        $this->encodes++;
        return $this->inner->encode($context);
    }

    public function decode(string $data): AuthContext
    {
        $this->decoded[] = $data;
        return $this->inner->decode($data);
    }
}

final class FailingCodec implements AuthContextCodec
{
    public function encode(AuthContext $context): string
    {
        throw new \LogicException('encode falhou');
    }

    public function decode(string $data): AuthContext
    {
        throw new \LogicException('decode falhou');
    }
}

final class RecordingEmitter implements CookieEmitter
{
    public array $headers = [];
    public ?\Throwable $failure = null;

    public function emit(string $header): void
    {
        if ($this->failure !== null) {
            throw $this->failure;
        }
        $this->headers[] = $header;
    }
}

final class RecordingFilter extends SecurityFilterChain
{
    public int $calls = 0;
    public ?AuthContext $seen = null;
    public bool $revoke = false;
    public ?AuthContext $replace = null;

    public function filterPerRequest(Request $req)
    {
        $this->calls++;
        $this->seen = SecurityContext::getContext();
        if ($this->revoke) {
            SecurityContext::clearContext();
        }
        if ($this->replace !== null) {
            SecurityContext::setContext($this->replace);
        }
    }
}

final class RoleValidator extends AuthorizationValidator
{
    public function __construct(private string $role)
    {
        parent::__construct([$role], "missing $role");
    }

    public function isValid(AuthContext $context): bool
    {
        return in_array($this->role, $context->getRoles(), true);
    }
}

final class DummyController
{
    #[Authorize(['adm'])]
    public function admin(): string { return 'admin'; }

    #[Authorize(new RoleValidator('finance'))]
    public function finance(): string { return 'finance'; }
}

final class Browser
{
    public array $jar = [];

    public function receive(RecordingEmitter $emitter): void
    {
        foreach ($emitter->headers as $header) {
            $parts = explode('; ', substr($header, strlen('Set-Cookie: ')));
            [$name, $value] = explode('=', array_shift($parts), 2);
            $deleted = in_array('Max-Age=0', $parts, true);
            if ($deleted) {
                unset($this->jar[$name]);
            } else {
                $this->jar[$name] = rawurldecode($value);
            }
        }
        $emitter->headers = [];
    }
}

$passed = 0;

function ensure(bool $condition, string $message): void
{
    global $passed;
    if (!$condition) {
        throw new RuntimeException($message);
    }
    $passed++;
}

function expectThrows(callable $action, string $class, string $message): \Throwable
{
    try {
        $action();
    } catch (\Throwable $e) {
        ensure($e instanceof $class, "$message: esperado $class, recebido " . get_class($e) . ' ' . $e->getMessage());
        return $e;
    }
    throw new RuntimeException("$message: nenhuma exceção lançada");
}

function section(string $name): void
{
    echo "- $name\n";
}

function newRequest(array $session = [], array $cookies = [], array $env = []): void
{
    $reflection = new ReflectionClass(HttpSecurityConfigurar::class);
    foreach (['requests' => [], 'filters' => [], 'defaultRoles' => [], 'defaultValidator' => null] as $property => $value) {
        $reflection->getProperty($property)->setValue(null, $value);
    }
    SecurityConfiguration::reset();
    $_SESSION = $session;
    $_COOKIE = $cookies;
    $_ENV = $env;
}

const COOKIE_NAME = 'http_security_context';

function testKey(): string
{
    static $key = null;
    return $key ??= base64_encode(random_bytes(32));
}

function cookieConfig(RecordingEmitter $emitter, ?AuthContextCodec $codec = null, array $options = []): HttpSecurityConfigurar
{
    SecurityConfiguration::setEmitter($emitter);
    $config = new HttpSecurityConfigurar();
    $config->sessionPolice(SessionPolice::STATEFULL, StatefulStorage::COOKIE)
        ->cookieOptions(new CookieOptions(...array_merge(['key' => testKey()], $options)));
    if ($codec !== null) {
        $config->contextCodec($codec);
    }
    return $config;
}

function forgeCookie(string $key, array $envelope, string $name = COOKIE_NAME, string $path = '/', string $domain = ''): string
{
    $iv = random_bytes(12);
    $tag = '';
    $aad = json_encode(['v1.', $name, $path, $domain], JSON_THROW_ON_ERROR);
    $cipher = openssl_encrypt(json_encode($envelope), 'aes-256-gcm', base64_decode($key), OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
    return 'v1.' . rtrim(strtr(base64_encode($iv . $tag . $cipher), '+/', '-_'), '=');
}

function middleware(HttpSecurityConfigurar $config): HttpSecurityMiddleware
{
    $middleware = new HttpSecurityMiddleware();
    (new ReflectionProperty($middleware, 'httpManager'))->setValue($middleware, $config);
    return $middleware;
}

function runMiddleware(HttpSecurityConfigurar $config, string $path, string $method = 'GET'): void
{
    $_SERVER['REQUEST_URI'] = $path;
    $_SERVER['REQUEST_METHOD'] = $method;
    $route = new Router($path, $method, new ReflectionClass(DummyController::class), new ReflectionMethod(DummyController::class, 'admin'));
    middleware($config)->onPerrequest(new Request([], [], [], $path, '127.0.0.1', $route));
}

function executeAspect(string $methodName): void
{
    $controller = new DummyController();
    $method = new ReflectionMethod($controller, $methodName);
    $args = [];
    $aspect = new AuthorizeAspect();
    ensure($aspect->pointCut($controller, $method, $args), "pointcut ausente em $methodName");
    $aspect->aspectBefore($controller, $method, $args);
}

function richContext(): RichContext
{
    $context = new RichContext(
        'maria',
        ['adm', 'finance'],
        new DateTimeImmutable('2030-01-02 03:04:05.123456', new DateTimeZone('America/Sao_Paulo')),
        new DateTime('2026-10-10 10:00:00', new DateTimeZone('UTC')),
        new SimpleContext('nested', ['n'], 'dev')
    );
    $context->extra = ['tenant' => 42, 'flags' => ['beta' => true]];
    return $context;
}

section('1. chamadas antigas, STATELESS e sessão STATEFULL');
newRequest();
$config = new HttpSecurityConfigurar();
ensure($config->getSessionPolice() === SessionPolice::STATELESS, 'STATELESS deve ser padrão');
SecurityContext::setContext(new SimpleContext());
ensure(SecurityContext::getContext()?->getUser() === 'ana', 'STATELESS mantém contexto em memória');
ensure($_SESSION === [], 'STATELESS não grava sessão');
newRequest($_SESSION);
ensure(SecurityContext::getContext() === null, 'STATELESS não persiste entre requisições');

newRequest();
$config = new HttpSecurityConfigurar();
$returned = $config->sessionPolice(SessionPolice::STATEFULL);
ensure($returned === $config, 'sessionPolice continua fluente');
ensure($config->getSessionPolice() === SessionPolice::STATEFULL, 'política STATEFULL registrada');
ensure($config->getStatefulStorage() === StatefulStorage::SESSION, 'sessão é armazenamento padrão');
$context = new SimpleContext('joao', ['user']);
SecurityContext::setContext($context);
ensure($_SESSION['Securitycontext'] === serialize($context), 'codec padrão grava exatamente serialize(context)');
ensure(!array_key_exists('SessionPolice', $_SESSION), 'política não é gravada na sessão');
$session = $_SESSION;
newRequest($session);
(new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATEFULL);
ensure(SecurityContext::getContext()?->getUser() === 'joao', 'sessão restaura contexto');
SecurityContext::clearContext();
ensure(!isset($_SESSION['Securitycontext']) && SecurityContext::getContext() === null, 'clear remove contexto da sessão');

section('2. codec interno automático');
newRequest();
$config = new HttpSecurityConfigurar();
ensure($config->getContextCodec() instanceof PhpSerializedAuthContextCodec, 'codec padrão é PhpSerializedAuthContextCodec');
$config->sessionPolice(SessionPolice::STATEFULL, StatefulStorage::COOKIE);
ensure($config->getContextCodec() instanceof PhpSerializedAuthContextCodec, 'codec padrão também no cookie');
$emitter = new RecordingEmitter();
cookieConfig($emitter);
SecurityContext::setContext(new SimpleContext('cookie-user'));
ensure(count($emitter->headers) === 1, 'cookie emitido pelo codec interno');

section('3. codec personalizado em sessão e cookie');
newRequest();
$codec = new JsonContextCodec();
$config = (new HttpSecurityConfigurar())
    ->sessionPolice(SessionPolice::STATEFULL, StatefulStorage::SESSION)
    ->contextCodec($codec);
ensure($config->getContextCodec() === $codec, 'getContextCodec retorna codec configurado');
SecurityContext::setContext(new SimpleContext('json', ['a']));
ensure($_SESSION['Securitycontext'] === '{"user":"json","roles":["a"],"environment":"prod"}', 'sessão guarda string do codec personalizado');
$session = $_SESSION;
newRequest($session);
$codec = new JsonContextCodec();
(new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATEFULL)->contextCodec($codec);
ensure(SecurityContext::getContext()?->getUser() === 'json' && $codec->decodes === 1, 'sessão lê com codec personalizado');

newRequest();
$browser = new Browser();
$emitter = new RecordingEmitter();
$codec = new JsonContextCodec();
cookieConfig($emitter, $codec);
SecurityContext::setContext(new SimpleContext('json-cookie', ['b']));
ensure($codec->encodes === 1, 'cookie usa encode do codec personalizado');
$browser->receive($emitter);
newRequest([], $browser->jar);
$codec = new JsonContextCodec();
cookieConfig($emitter, $codec);
ensure(SecurityContext::getContext()?->getRoles() === ['b'] && $codec->decodes === 1, 'cookie lê com codec personalizado');

section('4. codec não chamado em STATELESS');
newRequest();
$spy = new SpyCodec();
(new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATELESS)->contextCodec($spy);
SecurityContext::setContext(new SimpleContext());
SecurityContext::getContext();
SecurityContext::clearContext();
ensure($spy->encodes === 0 && $spy->decoded === [], 'codec não é usado em STATELESS');

section('5. sessão legada');
$legacy = new SimpleContext('legado', ['old'], 'hml');
newRequest(['Securitycontext' => serialize($legacy), 'SessionPolice' => SessionPolice::STATEFULL]);
(new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATEFULL);
ensure(SecurityContext::getContext() == $legacy, 'sessão antiga é lida sem migração');
newRequest(['Securitycontext' => serialize($legacy)]);
(new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATEFULL)->contextCodec(new LegacyAwareJsonCodec());
ensure(SecurityContext::getContext()?->getUser() === 'legado', 'codec personalizado pode ler formato antigo');

section('6. campos privados, readonly e datas');
foreach ([StatefulStorage::SESSION, StatefulStorage::COOKIE] as $storage) {
    newRequest();
    $browser = new Browser();
    $emitter = new RecordingEmitter();
    $original = richContext();
    $storage === StatefulStorage::COOKIE ? cookieConfig($emitter) : (new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATEFULL);
    SecurityContext::setContext($original);
    $browser->receive($emitter);
    $session = $storage === StatefulStorage::SESSION ? $_SESSION : [];
    newRequest($session, $browser->jar);
    $storage === StatefulStorage::COOKIE ? cookieConfig($emitter) : (new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATEFULL);
    $restored = SecurityContext::getContext();
    ensure($restored instanceof RichContext, "$storage preserva classe concreta");
    ensure($restored == $original, "$storage preserva propriedades");
    ensure($restored->getExpiresAt()->format('Y-m-d H:i:s.u e') === '2030-01-02 03:04:05.123456 America/Sao_Paulo', "$storage preserva DateTimeImmutable sem recalcular");
    ensure($restored->getLoggedAt() instanceof DateTime && $restored->getLoggedAt()->getTimestamp() === $original->getLoggedAt()->getTimestamp(), "$storage preserva DateTime");
    ensure($restored->getUserArgs()['nested'] instanceof SimpleContext, "$storage preserva objeto aninhado");
}

section('7. propriedades adicionais definidas por filtros');
newRequest();
$browser = new Browser();
$emitter = new RecordingEmitter();
$config = cookieConfig($emitter);
$filter = new RecordingFilter();
$filter->replace = richContext();
$config->AddFilterBefore($filter)->any()->permitAll();
runMiddleware($config, '/login');
$browser->receive($emitter);
newRequest([], $browser->jar);
cookieConfig($emitter);
$restored = SecurityContext::getContext();
ensure($restored instanceof RichContext && $restored->extra === ['tenant' => 42, 'flags' => ['beta' => true]], 'propriedades adicionais preservadas');

section('8. cookie restaura após perda da sessão PHP');
newRequest(['outro' => 'valor']);
$browser = new Browser();
$emitter = new RecordingEmitter();
cookieConfig($emitter);
SecurityContext::setContext(new SimpleContext('persistente'));
ensure(!isset($_SESSION['Securitycontext']), 'modo cookie não grava contexto na sessão');
$browser->receive($emitter);
newRequest([], $browser->jar);
cookieConfig($emitter);
ensure(SecurityContext::getContext()?->getUser() === 'persistente', 'cookie restaura sem sessão PHP');
ensure($emitter->headers === [], 'leitura não renova cookie');

section('9. migração sessão -> cookie');
$legacy = richContext();
newRequest(['Securitycontext' => serialize($legacy), 'outro' => 1]);
$browser = new Browser();
$emitter = new RecordingEmitter();
cookieConfig($emitter);
ensure(SecurityContext::getContext() == $legacy, 'contexto migrado preservado');
ensure(count($emitter->headers) === 1 && str_contains($emitter->headers[0], 'Max-Age=2592000'), 'migração emite cookie');
ensure(!isset($_SESSION['Securitycontext']) && $_SESSION['outro'] === 1, 'migração remove somente Securitycontext');
$browser->receive($emitter);
newRequest([], $browser->jar);
cookieConfig($emitter);
ensure(SecurityContext::getContext() == $legacy, 'cookie migrado restaura datas e propriedades');

newRequest(['Securitycontext' => serialize($legacy)]);
$emitter = new RecordingEmitter();
$emitter->failure = new RuntimeException('falha emissor');
cookieConfig($emitter);
ensure(SecurityContext::getContext() == $legacy, 'falha na migração mantém contexto da sessão');
ensure(isset($_SESSION['Securitycontext']), 'falha na migração preserva sessão');

newRequest(['Securitycontext' => serialize(new SimpleContext('antigo')), 'outro' => 1]);
$browser = new Browser();
$emitter = new RecordingEmitter();
cookieConfig($emitter);
SecurityContext::setContext(new SimpleContext('novo-login'));
ensure(!isset($_SESSION['Securitycontext']) && $_SESSION['outro'] === 1, 'login em modo cookie remove cópia legada da sessão');
$browser->receive($emitter);
newRequest($_SESSION);
cookieConfig($emitter);
ensure(SecurityContext::getContext() === null, 'cópia legada não ressuscita após perda do cookie');

newRequest(['Securitycontext' => serialize($legacy)], [COOKIE_NAME => 'v1.invalido']);
$emitter = new RecordingEmitter();
cookieConfig($emitter);
ensure(SecurityContext::getContext() === null, 'cookie inválido impede fallback para sessão');

section('10. precedência e validação da configuração');
newRequest([], [], ['HTTP_SECURITY_STATEFUL_STORAGE' => 'cookie']);
$config = new HttpSecurityConfigurar();
ensure($config->getStatefulStorage() === StatefulStorage::COOKIE, 'ambiente define armazenamento');
$config->sessionPolice(SessionPolice::STATEFULL, StatefulStorage::SESSION);
ensure($config->getStatefulStorage() === StatefulStorage::SESSION, 'código prevalece sobre ambiente');
$config->statefulStorage(StatefulStorage::COOKIE);
ensure($config->getStatefulStorage() === StatefulStorage::COOKIE, 'última escolha explícita prevalece');
$config->sessionPolice(SessionPolice::STATEFULL);
ensure($config->getStatefulStorage() === StatefulStorage::COOKIE, 'sessionPolice sem armazenamento preserva escolha');
newRequest();
ensure((new HttpSecurityConfigurar())->getStatefulStorage() === StatefulStorage::SESSION, 'sessão é padrão sem ambiente');
expectThrows(fn () => (new HttpSecurityConfigurar())->sessionPolice(7), InvalidArgumentException::class, 'política inválida');
expectThrows(fn () => (new HttpSecurityConfigurar())->statefulStorage('redis'), InvalidArgumentException::class, 'armazenamento inválido');
expectThrows(fn () => (new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATEFULL, 'redis'), InvalidArgumentException::class, 'armazenamento inválido em sessionPolice');
ensure((new HttpSecurityConfigurar())->getSessionPolice() === SessionPolice::STATELESS, 'falha de validação não altera política');
newRequest([], [], ['HTTP_SECURITY_STATEFUL_STORAGE' => 'memcached']);
expectThrows(fn () => (new HttpSecurityConfigurar())->getStatefulStorage(), InvalidArgumentException::class, 'armazenamento inválido no ambiente');

newRequest([], [], [
    'HTTP_SECURITY_COOKIE_NAME' => 'env_name',
    'HTTP_SECURITY_COOKIE_TTL' => '60',
    'HTTP_SECURITY_COOKIE_PATH' => '/app',
    'HTTP_SECURITY_COOKIE_DOMAIN' => 'example.com',
    'HTTP_SECURITY_COOKIE_SECURE' => 'true',
    'HTTP_SECURITY_COOKIE_SAME_SITE' => 'Strict',
    'HTTP_SECURITY_COOKIE_KEY' => testKey(),
]);
$resolved = (new CookieOptions(name: 'code_name', secure: false, domain: ''))->resolve();
ensure($resolved->name === 'code_name' && $resolved->secure === false && $resolved->domain === '', 'código prevalece sobre ambiente, inclusive false e vazio');
ensure($resolved->ttl === 60 && $resolved->path === '/app' && $resolved->sameSite === 'Strict' && $resolved->key === testKey(), 'ambiente prevalece sobre padrão');
newRequest();
$defaults = (new CookieOptions())->resolve();
ensure($defaults->name === 'http_security_context' && $defaults->ttl === 2592000 && $defaults->path === '/'
    && $defaults->domain === '' && $defaults->secure === true && $defaults->sameSite === 'Lax', 'padrões documentados');
foreach ([
    'TTL inválido' => ['HTTP_SECURITY_COOKIE_TTL' => 'abc'],
    'TTL zero' => ['HTTP_SECURITY_COOKIE_TTL' => '0'],
    'TTL negativo' => ['HTTP_SECURITY_COOKIE_TTL' => '-5'],
    'booleano inválido' => ['HTTP_SECURITY_COOKIE_SECURE' => 'yes'],
    'SameSite inválido' => ['HTTP_SECURITY_COOKIE_SAME_SITE' => 'Loose'],
    'None sem Secure' => ['HTTP_SECURITY_COOKIE_SAME_SITE' => 'None', 'HTTP_SECURITY_COOKIE_SECURE' => 'false'],
    'nome inválido' => ['HTTP_SECURITY_COOKIE_NAME' => 'a.b'],
    'path inválido' => ['HTTP_SECURITY_COOKIE_PATH' => 'app; Secure'],
    'domain inválido' => ['HTTP_SECURITY_COOKIE_DOMAIN' => 'exa mple.com'],
] as $label => $env) {
    newRequest([], [], $env);
    expectThrows(fn () => (new CookieOptions())->resolve(), InvalidArgumentException::class, $label);
}
expectThrows(fn () => (new CookieOptions(ttl: 0))->resolve(), InvalidArgumentException::class, 'TTL explícito inválido');
foreach (['vazia' => '', 'curta' => base64_encode(random_bytes(16)), 'não canônica' => rtrim(testKey(), '='), 'não base64' => str_repeat('*', 44)] as $label => $key) {
    newRequest([], [], ['HTTP_SECURITY_COOKIE_KEY' => $key]);
    SecurityConfiguration::setEmitter(new RecordingEmitter());
    (new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATEFULL, StatefulStorage::COOKIE);
    expectThrows(fn () => SecurityContext::getContext(), InvalidArgumentException::class, "chave $label sem fallback silencioso");
}
newRequest(['Securitycontext' => serialize(new SimpleContext('sessao'))], [], ['HTTP_SECURITY_COOKIE_KEY' => 'invalida', 'HTTP_SECURITY_COOKIE_TTL' => 'x']);
(new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATEFULL);
ensure(SecurityContext::getContext()?->getUser() === 'sessao', 'requisitos do cookie só validados em STATEFULL + COOKIE');
newRequest();
$emitter = new RecordingEmitter();
cookieConfig($emitter, null, ['path' => '/app', 'domain' => 'example.com', 'sameSite' => 'Strict', 'ttl' => 120]);
SecurityContext::setContext(new SimpleContext());
$header = $emitter->headers[0];
ensure(str_starts_with($header, 'Set-Cookie: http_security_context=v1.'), 'nome e versão do cookie');
foreach (['; Path=/app', '; Domain=example.com', '; Secure', '; HttpOnly', '; SameSite=Strict', '; Max-Age=120', '; Expires='] as $attribute) {
    ensure(str_contains($header, $attribute), "atributo $attribute presente");
}
newRequest();
$emitter = new RecordingEmitter();
cookieConfig($emitter, null, ['secure' => false]);
SecurityContext::setContext(new SimpleContext());
ensure(!str_contains($emitter->headers[0], '; Secure') && str_contains($emitter->headers[0], '; HttpOnly'), 'Secure=false explícito mantém HttpOnly');

section('11. expiração absoluta, adulteração, chave errada e formato inválido');
$payload = base64_encode(serialize(new SimpleContext('forjado')));
$now = time();
$invalidCookies = [
    'expirado' => forgeCookie(testKey(), ['version' => 1, 'issuedAt' => $now - 100, 'expiresAt' => $now - 1, 'context' => $payload]),
    'expira agora' => forgeCookie(testKey(), ['version' => 1, 'issuedAt' => $now - 100, 'expiresAt' => $now, 'context' => $payload]),
    'versão errada' => forgeCookie(testKey(), ['version' => 2, 'issuedAt' => $now, 'expiresAt' => $now + 100, 'context' => $payload]),
    'envelope sem contexto' => forgeCookie(testKey(), ['version' => 1, 'issuedAt' => $now, 'expiresAt' => $now + 100]),
    'contexto não base64' => forgeCookie(testKey(), ['version' => 1, 'issuedAt' => $now, 'expiresAt' => $now + 100, 'context' => '***']),
    'chave errada' => forgeCookie(base64_encode(random_bytes(32)), ['version' => 1, 'issuedAt' => $now, 'expiresAt' => $now + 100, 'context' => $payload]),
    'outro path' => forgeCookie(testKey(), ['version' => 1, 'issuedAt' => $now, 'expiresAt' => $now + 100, 'context' => $payload], COOKIE_NAME, '/admin'),
    'outro nome' => forgeCookie(testKey(), ['version' => 1, 'issuedAt' => $now, 'expiresAt' => $now + 100, 'context' => $payload], 'other'),
    'outro domain' => forgeCookie(testKey(), ['version' => 1, 'issuedAt' => $now, 'expiresAt' => $now + 100, 'context' => $payload], COOKIE_NAME, '/', 'evil.com'),
    'sem prefixo' => 'abc',
    'versão v2' => 'v2.abcdef',
    'base64 inválido' => 'v1.@@@@',
    'curto' => 'v1.' . rtrim(strtr(base64_encode(random_bytes(20)), '+/', '-_'), '='),
    'grande' => 'v1.' . str_repeat('A', 5000),
    'array' => ['v1.x'],
];
$valid = forgeCookie(testKey(), ['version' => 1, 'issuedAt' => $now, 'expiresAt' => $now + 100, 'context' => $payload]);
$tampered = $valid;
$tampered[20] = $tampered[20] === 'A' ? 'B' : 'A';
$invalidCookies['adulterado'] = $tampered;
$invalidCookies['padding'] = $valid . '=';
foreach ($invalidCookies as $label => $cookie) {
    newRequest([], [COOKIE_NAME => $cookie]);
    $emitter = new RecordingEmitter();
    $spy = new SpyCodec();
    cookieConfig($emitter, $spy);
    ensure(SecurityContext::getContext() === null, "cookie $label retorna null");
    ensure($spy->decoded === [], "cookie $label não chega ao codec");
    ensure(count($emitter->headers) === 1 && str_contains($emitter->headers[0], 'Max-Age=0'), "cookie $label tenta exclusão");
    ensure(!isset($_COOKIE[COOKIE_NAME]), "cookie $label removido da requisição");
}
newRequest([], [COOKIE_NAME => $valid]);
$emitter = new RecordingEmitter();
$spy = new SpyCodec();
cookieConfig($emitter, $spy);
ensure(SecurityContext::getContext()?->getUser() === 'forjado' && count($spy->decoded) === 1, 'cookie autenticado chega ao codec');
newRequest([], [COOKIE_NAME => $invalidCookies['expirado']]);
$emitter = new RecordingEmitter();
$emitter->failure = new RuntimeException('falha');
cookieConfig($emitter);
ensure(SecurityContext::getContext() === null, 'falha ao excluir cookie inválido não impede retorno null');

section('12. conteúdo não autenticado nunca chega ao codec');
newRequest([], [COOKIE_NAME => 'v1.' . rtrim(strtr(base64_encode(random_bytes(12) . random_bytes(16) . serialize(new SimpleContext())), '+/', '-_'), '=')]);
$spy = new SpyCodec();
cookieConfig(new RecordingEmitter(), $spy);
ensure(SecurityContext::getContext() === null && $spy->decoded === [], 'cookie sem autenticação válida não chega ao codec');
newRequest([], [COOKIE_NAME => serialize(new SimpleContext())]);
$spy = new SpyCodec();
cookieConfig(new RecordingEmitter(), $spy);
ensure(SecurityContext::getContext() === null && $spy->decoded === [], 'serialização direta no cookie é rejeitada');

section('13. falhas de encode/decode, classes ausentes e formatos incompatíveis');
foreach ([StatefulStorage::SESSION, StatefulStorage::COOKIE] as $storage) {
    newRequest();
    $emitter = new RecordingEmitter();
    $storage === StatefulStorage::COOKIE ? cookieConfig($emitter) : (new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATEFULL);
    SecurityContext::setContext(new SimpleContext('anterior'));
    $before = $_SESSION;
    $headers = count($emitter->headers);
    (new HttpSecurityConfigurar())->contextCodec(new FailingCodec());
    expectThrows(fn () => SecurityContext::setContext(new SimpleContext('novo')), RuntimeException::class, "$storage encode com falha");
    ensure($_SESSION === $before && count($emitter->headers) === $headers, "$storage encode com falha não altera persistência");
}
newRequest(['Securitycontext' => serialize(new SimpleContext())]);
(new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATEFULL)->contextCodec(new FailingCodec());
ensure(SecurityContext::getContext() === null && !isset($_SESSION['Securitycontext']), 'decode com falha invalida sessão');
$missing = 'O:18:"MissingContextType":1:{s:4:"user";s:3:"ana";}';
$nestedMissing = str_replace('O:13:"SimpleContext"', 'O:13:"MissingNested"', serialize(new RichContext('x', [], new DateTimeImmutable(), new DateTime(), new SimpleContext())));
foreach ([
    'classe ausente' => $missing,
    'classe aninhada ausente' => $nestedMissing,
    'json com codec padrão' => '{"user":"x"}',
    'serialização truncada' => substr(serialize(new SimpleContext()), 0, 20),
    'não AuthContext' => serialize(new ArrayObject()),
    'escalar' => serialize(false),
    'tipo inválido na sessão' => ['array'],
] as $label => $data) {
    newRequest(['Securitycontext' => $data, 'outro' => 1]);
    (new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATEFULL);
    ensure(SecurityContext::getContext() === null, "sessão com $label retorna null");
    ensure(!isset($_SESSION['Securitycontext']) && $_SESSION['outro'] === 1, "sessão com $label remove somente o contexto");
}
newRequest(['Securitycontext' => serialize(new SimpleContext())]);
(new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATEFULL)->contextCodec(new JsonContextCodec());
ensure(SecurityContext::getContext() === null, 'troca de codec sem compatibilidade exige novo login');
$codec = new PhpSerializedAuthContextCodec();
expectThrows(fn () => $codec->decode($missing), UnexpectedValueException::class, 'codec interno rejeita classe ausente');
ensure(set_error_handler(null) === null, 'codec restaura tratamento de erros do processo');
restore_error_handler();
newRequest();
$browser = new Browser();
$emitter = new RecordingEmitter();
cookieConfig($emitter, new JsonContextCodec());
SecurityContext::setContext(new SimpleContext('json'));
$browser->receive($emitter);
newRequest([], $browser->jar);
cookieConfig($emitter);
ensure(SecurityContext::getContext() === null, 'cookie com formato incompatível retorna null');

section('14. tamanho, falha do emissor e cabeçalhos enviados');
newRequest();
$emitter = new RecordingEmitter();
cookieConfig($emitter);
SecurityContext::setContext(new SimpleContext('atual'));
$cookie = $_COOKIE[COOKIE_NAME];
expectThrows(fn () => SecurityContext::setContext(new SimpleContext('grande', [str_repeat('r', 4000)])), LengthException::class, 'contexto excede 4096 bytes');
ensure(SecurityContext::getContext()?->getUser() === 'atual' && $_COOKIE[COOKIE_NAME] === $cookie && count($emitter->headers) === 1, 'tamanho excessivo não substitui contexto atual');
$emitter->failure = new RuntimeException('emissor');
expectThrows(fn () => SecurityContext::setContext(new SimpleContext('novo')), RuntimeException::class, 'falha do emissor');
ensure(SecurityContext::getContext()?->getUser() === 'atual', 'falha do emissor não indica sucesso');
$emitter->failure = null;
SecurityContext::setContext(new SimpleContext('limite', [str_repeat('r', 2000)]));
ensure(strlen($emitter->headers[1]) <= 4096, 'cabeçalho emitido respeita limite');
echo "  (saída enviada para validar headers_sent)\n";
expectThrows(fn () => (new NativeCookieEmitter())->emit('Set-Cookie: a=b'), RuntimeException::class, 'cabeçalhos já enviados');
newRequest();
SecurityConfiguration::setEmitter(null);
(new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATEFULL, StatefulStorage::COOKIE)->cookieOptions(new CookieOptions(key: testKey()));
expectThrows(fn () => SecurityContext::setContext(new SimpleContext()), RuntimeException::class, 'emissor nativo após saída');
ensure(SecurityContext::getContext() === null, 'contexto não definido após falha nativa');

section('15. logout sem restauração na mesma requisição');
newRequest();
$browser = new Browser();
$emitter = new RecordingEmitter();
cookieConfig($emitter, null, ['path' => '/app', 'domain' => 'example.com']);
SecurityContext::setContext(new SimpleContext('logado'));
$browser->receive($emitter);
$oldCookie = $browser->jar[COOKIE_NAME];
newRequest(['Securitycontext' => serialize(new SimpleContext('legado')), 'outro' => 1], $browser->jar);
cookieConfig($emitter, null, ['path' => '/app', 'domain' => 'example.com']);
ensure(SecurityContext::getContext()?->getUser() === 'logado', 'cookie restaurado antes do logout');
SecurityContext::clearContext();
$_COOKIE[COOKIE_NAME] = $oldCookie;
ensure(SecurityContext::getContext() === null, 'clear ignora $_COOKIE antigo na mesma requisição');
ensure(SecurityContext::getContext() === null, 'getContext após clear permanece null');
ensure(!isset($_SESSION['Securitycontext']) && $_SESSION['outro'] === 1, 'clear remove sessão legada sem destruir sessão');
$deletion = $emitter->headers[0];
ensure(str_contains($deletion, 'http_security_context=;') && str_contains($deletion, 'Max-Age=0')
    && str_contains($deletion, 'Path=/app') && str_contains($deletion, 'Domain=example.com'), 'exclusão usa mesmo nome/path/domain');
SecurityContext::setContext(new SimpleContext('novo'));
ensure(SecurityContext::getContext()?->getUser() === 'novo', 'set após clear retorna novo contexto imediatamente');
$emitter->failure = new RuntimeException('emissor');
expectThrows(fn () => SecurityContext::clearContext(), RuntimeException::class, 'clear comunica falha do navegador');
ensure(SecurityContext::getContext() === null && !isset($_COOKIE[COOKIE_NAME]), 'clear limpa local mesmo com falha');

section('16. filtros uma vez e revogação antes da autorização');
newRequest();
$browser = new Browser();
$emitter = new RecordingEmitter();
cookieConfig($emitter);
SecurityContext::setContext(new SimpleContext('filtrado', ['adm']));
$browser->receive($emitter);
foreach (['/public' => false, '/api/item' => true, '/other' => true] as $path => $protected) {
    newRequest([], $browser->jar);
    $config = cookieConfig($emitter);
    $filter = new RecordingFilter();
    $config->RequestPatterns(function (RequestMatcherAction $e) {
        $e->Request('/public')->permitAll();
        $e->Request('/api/**')->authenticate('adm');
        $e->Request('/api/item')->authenticate('adm');
    })->AddFilterBefore($filter)->any()->authenticate();
    runMiddleware($config, $path);
    ensure($filter->calls === 1, "filtro executado uma vez em $path");
    ensure($filter->seen?->getUser() === 'filtrado', "filtro enxerga contexto restaurado em $path");
}
newRequest([], $browser->jar);
$config = cookieConfig($emitter);
$filter = new RecordingFilter();
$config->any()->permitAll();
$config->AddFilterBefore($filter);
runMiddleware($config, '/qualquer');
ensure($filter->calls === 1, 'filtro executado em any público');
foreach (['/api/item', '/other'] as $path) {
    newRequest([], $browser->jar);
    $config = cookieConfig($emitter);
    $filter = new RecordingFilter();
    $filter->revoke = true;
    $config->RequestPatterns(function (RequestMatcherAction $e) {
        $e->Request('/api/**')->authenticate('adm');
    })->AddFilterBefore($filter)->any()->authenticate();
    expectThrows(fn () => runMiddleware($config, $path), AuthorizationException::class, "revogação no filtro bloqueia $path");
}

section('17. ausência de vazamento entre requisições');
newRequest();
$emitter = new RecordingEmitter();
cookieConfig($emitter);
SecurityContext::setContext(new SimpleContext('usuario-a'));
newRequest();
cookieConfig(new RecordingEmitter());
ensure(SecurityContext::getContext() === null, 'contexto de cookie não vaza para requisição sem cookie');
newRequest();
SecurityContext::setContext(new SimpleContext('memoria'));
newRequest();
ensure(SecurityContext::getContext() === null, 'contexto STATELESS não vaza');
newRequest(['Securitycontext' => serialize(new SimpleContext('sessao-b'))]);
(new HttpSecurityConfigurar())->sessionPolice(SessionPolice::STATEFULL);
ensure(SecurityContext::getContext()?->getUser() === 'sessao-b', 'cache por requisição não reaproveita usuário anterior');

section('18. roles, validators, ambientes e atributos preservados');
newRequest();
$browser = new Browser();
$emitter = new RecordingEmitter();
cookieConfig($emitter);
SecurityContext::setContext(new SimpleContext('roles', ['adm', 'finance'], 'prod'));
$browser->receive($emitter);
$scenarios = [
    ['/admin', 'adm', 'prod', null],
    ['/admin', 'missing', 'prod', AuthorityAuthorizationException::class],
    ['/admin', 'adm', 'dev', EnvironmentAuthorizationException::class],
    ['/admin', new RoleValidator('finance'), 'prod', null],
    ['/admin', new RoleValidator('ops'), 'prod', AuthorityAuthorizationException::class],
];
foreach ($scenarios as [$path, $authorization, $environment, $expected]) {
    newRequest([], $browser->jar);
    $config = cookieConfig($emitter);
    $config->RequestPatterns(function (RequestMatcherAction $e) use ($path, $authorization, $environment) {
        $e->Request($path, $environment)->authenticate($authorization);
    });
    if ($expected === null) {
        runMiddleware($config, $path);
        ensure(true, 'autorização aceita');
    } else {
        expectThrows(fn () => runMiddleware($config, $path), $expected, 'autorização negada');
    }
}
newRequest([], $browser->jar);
$config = cookieConfig($emitter);
$config->any()->authenticate(['adm']);
$config->defaultEnvaroment('prod');
runMiddleware($config, '/default');
ensure(true, 'any com roles e ambiente padrão');
$config->defaultEnvaroment('hml');
expectThrows(fn () => runMiddleware($config, '/default'), EnvironmentAuthorizationException::class, 'ambiente padrão diferente');
newRequest([], $browser->jar);
cookieConfig($emitter);
executeAspect('admin');
executeAspect('finance');
ensure(true, 'atributos com contexto restaurado');

echo "persistence-test: OK ($passed verificações)\n";
