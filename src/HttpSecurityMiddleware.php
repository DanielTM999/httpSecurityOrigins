<?php
    namespace Daniel\HttpSecurity;
    
    use Daniel\Origins\DependencyManager;
    use Daniel\Origins\HttpMethod;
    use Daniel\Origins\Inject;
    use Daniel\Origins\Middleware;
    use Daniel\Origins\Request;
    use Exception;
    use Override;

    class HttpSecurityMiddleware extends Middleware{

        #[Inject]
        private HttpSecurityConfigurar $httpManager;

        private HttpSecurityConfigurarEnv $environment;

        #[Override]
        public function onPerrequest(Request $req) : void{
            $requestPath = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
            $requestMethod = $_SERVER['REQUEST_METHOD'];
            $userDatails = SecurityContext::getContext();

            if(!isset($userDatails)){
                $this->environment = $this->httpManager->getDefaultEnv();
                if(!isset($this->environment)){
                    return;
                }
            }else{
                $environmentName = $userDatails->getEnvironment();
                if(!isset($environmentName)){
                    return;
                }else{
                    $this->environment = $this->httpManager->getEnviroment($environmentName);
                    if(!isset($this->environment)){
                        return;
                    }
                }
            }

            foreach($this->environment->getREQUESTS() as $r) { 
                $routeSecurity = $r->getRoute();
                if(strpos($routeSecurity, "/**") !== false){
                    $routePrefix = rtrim($routeSecurity, '/**');
                    if (strpos($requestPath, $routePrefix) === 0) {
                        $method = $r->getHttpMethod();
                        if(!isset($method)){
                            $not = $this->authAction($routeSecurity, $requestPath, $r, $req, true);
                            if($not){
                                return ;
                            }
                        }else{
                            if($method === $requestMethod){
                                $not = $this->authAction($routeSecurity, $requestPath, $r, $req, true);
                                if($not){
                                    return ;
                                }
                            }
                        }
                    }
                }else{
                    $method = $r->getHttpMethod();
                    if(!isset($method)){
                        $not = $this->authAction($routeSecurity, $requestPath, $r, $req);
                        if($not){
                            return ;
                        }
                    }else{
                        if($method === $requestMethod){
                            $not = $this->authAction($routeSecurity, $requestPath, $r, $req);
                            if($not){
                                return ;
                            }
                        }
                    }
                    
                }
            }

            if(!$this->environment->ispublic()){
                if($this->environment->getSessionPolice() === SessionPolice::STATELESS){
                    $_SESSION["SessionPolice"] = SessionPolice::STATELESS;
                }else{
                    $_SESSION["SessionPolice"] = SessionPolice::STATEFULL;
                }

                $userDatails = SecurityContext::getContext();
                if(!isset($userDatails)){
                    throw new AuthorizationException("not authorized ");
                }else{
                    if(!empty($roles)){
                        if (empty(array_intersect($roles, $userDatails->getRoles()))) {
                            throw new AuthorityAuthorizationException("not authorized [not conteins permission Role]");
                        }
                    }
                }
            }
        }

        private function authAction($routeSecurity, $requestPath, RequestMatcher $r, Request $req, bool $verifiMethod = false){
            $this->applyFilters($req);
            if($routeSecurity === $requestPath || $verifiMethod){
                if($r->getNeedAuth()){
                    if($this->isAuth($r->getRoles(), $r->getenvironment())){
                        return true;
                    }
                    throw new AuthorizationException("not authorized ");
                }else{
                    return true;
                }
            }
            return false;
        }

        public function isAuth($roles, $environment): bool{
            $environment = $environment ?? "";
            if($this->environment->getSessionPolice() === SessionPolice::STATELESS){
                $_SESSION["SessionPolice"] = SessionPolice::STATELESS;
            }else{
                $_SESSION["SessionPolice"] = SessionPolice::STATEFULL;
            }

            $userDatails = SecurityContext::getContext();

            if(!isset($userDatails)){
                return false;
            }

            if($environment !== ""){
                if($userDatails->getEnvironment() === null){
                    throw new EnvironmentAuthorizationException("not authorized [not conteins permission Enviroment]");
                }else if($userDatails->getEnvironment() !== $environment){
                    throw new EnvironmentAuthorizationException("not authorized [not conteins permission Enviroment]");
                }
            }

            if(!empty($roles)){
                if (!empty(array_intersect($roles, $userDatails->getRoles()))) {
                    return true;
                }
                throw new AuthorityAuthorizationException("not authorized [not conteins permission Role]");
            }else{
                return true;
            }
        }

        private function applyFilters(Request $req){
            foreach($this->environment->getFilters() as $r){
                try {
                    $r->filterPerRequest($req);
                } catch (\Throwable $th) {
                    throw $th;
                }
            }
        }

    }

    class AuthorizationException extends Exception{

        public function __construct($message = "Authorization error", $code = 0, Exception|null $previous = null)
        {
            parent::__construct($message, $code, $previous);
        }
    }

    class AuthorityAuthorizationException extends Exception{

        public function __construct($message = "Authorization Roles error", $code = 0, Exception|null $previous = null)
        {
            parent::__construct($message, $code, $previous);
        }
    }

    class EnvironmentAuthorizationException extends Exception{

        public function __construct($message = "Authorization Environment error", $code = 0, Exception|null $previous = null)
        {
            parent::__construct($message, $code, $previous);
        }
    }
?>