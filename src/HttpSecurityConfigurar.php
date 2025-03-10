<?php
    namespace Daniel\HttpSecurity;

    use Daniel\Origins\DependencyManager;
    use Daniel\Origins\FilterPriority;
    use Daniel\Origins\Inject;
    use Daniel\Origins\OnInit;
    use InvalidArgumentException;
    use Override;
    use ReflectionClass;

    #[FilterPriority(99999)]
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
        private array $enviroments;
        private string $defaultEnvName = ""; 
        
        public function addEnvaroment(bool $default = true, string $envName = "default", callable $function){
            $env = new HttpSecurityConfigurarEnv($envName);
            $function($env);
            $this->enviroments[$envName] = $env;
            if($default){
                $this->defaultEnvName = $envName;
            }
        }

        public function getDefaultEnv(){
            return  $this->enviroments[$this->defaultEnvName] ?? null;
        }

        public function getEnviroments(): array{
            return $this->enviroments;
        }

        public function getEnviroment(string $envName){
            return $this->enviroments[$envName] ?? null;
        }

    }
    
    class HttpSecurityConfigurarEnv{
        private static int $sessionPolice = SessionPolice::STATELESS;
        private static $requests = [];
        private static $filters = [];
        private bool $anyPublic = true;
        private string $envName;

        public function __construct(string $envName){
            $this->envName = $envName;
        }
        
        public function sessionPolice(int $police): HttpSecurityConfigurarEnv{
            self::$sessionPolice = $police;
            return $this;
        }

        public function RequestPatterns(callable $f): HttpSecurityConfigurarEnv{
            $f(new RequestMatcherAction($this, $this->envName));
            return $this;
        }

        public function AddRequestMatcher(RequestMatcher $requestMatcher): void{
            self::$requests[] = $requestMatcher;
        }

        public function AddFilterBefore(object &$filter): HttpSecurityConfigurarEnv{
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
        private string $environment;

        public function __construct(string $route, $httpMethod, bool $permit, array $roles, string $environment)
        {
            $this->route = $route;
            $this->httpMethod = $httpMethod;
            $this->needAuth = $permit;
            $this->roles = $roles;
            $this->environment = $environment;
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
        public function getEnvironment(): string{
            return $this->environment;
        }
    }

    class RequestMatcherAction{
        private HttpSecurityConfigurarEnv $config;
        private string $envName;

        public function __construct(HttpSecurityConfigurarEnv $config, string $envName)
        {
            $this->config = $config;
            $this->envName = $envName;
        }

        public function Request(string $route, $method = null): RequestMatcherActionAuthorize{
            return new RequestMatcherActionAuthorize($route, $this->config, $method, $this->envName);
        }
    }

    class RequestMatcherActionAuthorize{
        private HttpSecurityConfigurarEnv $config;
        private string $route;
        private $method;
        private string $environment;

        public function __construct(string $route, HttpSecurityConfigurarEnv $config, $method = null, $environment = null)
        {
            $this->route = $route;
            $this->method = $method;
            $this->config = $config;
            $this->environment = $environment ?? "";
        }

        public function authenticate(array $roles = []): void{
            $this->config->AddRequestMatcher(new RequestMatcher($this->route, $this->method, true, $roles, $this->environment));
        }

        public function permitAll(): void{
            $this->config->AddRequestMatcher(new RequestMatcher($this->route, $this->method, false, [], $this->environment));
        }
    }

    class RequestMatcherActionAuthorizeAny{
        private HttpSecurityConfigurarEnv $config;

        public function __construct(HttpSecurityConfigurarEnv $config)
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