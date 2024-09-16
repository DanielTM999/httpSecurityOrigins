<?php
    namespace Daniel\HttpSecurity;
    use Daniel\Origins\DependencyManager;
    use Daniel\Origins\FilterPriority;
    use Daniel\Origins\Inject;
    use Daniel\Origins\OnInit;
    use InvalidArgumentException;
    use Override;
    use ReflectionClass;

    #[FilterPriority(9999999)]
    class HttpSecurityConfigurarInit extends OnInit{

        #[Inject]
        private DependencyManager $manager;

        #[Override]
        public function ConfigOnInit() : void{
            $obj = new HttpSecurityConfigurar();
            $this->manager->addDependency(HttpSecurityConfigurar::class, $obj);
        }
    }

    class HttpSecurityConfigurar{
        private static int $sessionPolice = SessionPolice::STATELESS;
        private static $requests = [];
        private static $filters = [];
        private bool $anyPublic = true;
        
        public function sessionPolice(int $police): HttpSecurityConfigurar{
            self::$sessionPolice = $police;
            return $this;
        }

        public function RequestPatterns(callable $f): HttpSecurityConfigurar{
            $f(new RequestMatcherAction($this));
            return $this;
        }

        public function AddRequestMatcher(RequestMatcher $requestMatcher): void{
            self::$requests[] = $requestMatcher;
        }

        public function AddFilterBefore(object $filter): HttpSecurityConfigurar{
            if ($filter instanceof SecurityFilterChain) {
                self::$filters[] = $filter;
            } else {
                throw new InvalidArgumentException('O filtro deve ser uma instância de SecurityFilterChain.');
            }
            return $this;
        }

        public function any(): RequestMatcherActionAuthorizeAny{
            return new RequestMatcherActionAuthorizeAny($this);
        }

        public function getREQUESTS(){
            return self::$requests;
        }

        public function getFilters(){
            return self::$filters;
        }

        public function getSessionPolice(){
            return self::$sessionPolice;
        }

        public function ispublic(){
            return $this->anyPublic;
        }

    }

    class RequestMatcher{
        private string $route;
        private $httpMethod;
        private bool $needAuth;
        private array $roles;

        public function __construct(string $route, $httpMethod, bool $permit, array $roles)
        {
            $this->route = $route;
            $this->httpMethod = $httpMethod;
            $this->needAuth = $permit;
            $this->roles = $roles;
        }

        public function getRoute(): string{
            return $this->route;
        }

        public function getHttpMethod(){
            return $this->httpMethod;
        }
        public function getNeedAuth(): bool{
            return $this->needAuth;
        }
        public function getRoles(): array{
            return $this->roles;
        }
    }

    class RequestMatcherAction{
        private HttpSecurityConfigurar $config;

        public function __construct(HttpSecurityConfigurar $config)
        {
            $this->config = $config;
        }

        public function Request(string $route, $method = null): RequestMatcherActionAuthorize{
            return new RequestMatcherActionAuthorize($route, $this->config, $method);
        }
    }

    class RequestMatcherActionAuthorize{
        private HttpSecurityConfigurar $config;
        private string $route;
        private $method;

        public function __construct(string $route, HttpSecurityConfigurar $config, $method = null)
        {
            $this->route = $route;
            $this->method = $method;
            $this->config = $config;
        }

        public function authenticate(array $roles = []): void{
            $this->config->AddRequestMatcher(new RequestMatcher($this->route, $this->method, true, $roles));
        }

        public function permitAll(): void{
            $this->config->AddRequestMatcher(new RequestMatcher($this->route, $this->method, false, []));
        }
    }

    class RequestMatcherActionAuthorizeAny{
        private HttpSecurityConfigurar $config;

        public function __construct(HttpSecurityConfigurar $config)
        {
            $this->config = $config;
        }

        public function authenticate(): void{
            $reflect = new ReflectionClass($this->config);
            $var = $reflect->getProperty("anyPublic");
            $var->setValue($this->config, false);
        }

        public function permitAll(): void{
            $reflect = new ReflectionClass($this->config);
            $var = $reflect->getProperty("anyPublic");
            $var->setValue($this->config, true);
        }
    }

    class SessionPolice{
        const STATEFULL = 0;
        const STATELESS = 1;
    }

?>