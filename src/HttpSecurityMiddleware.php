<?php
    namespace Daniel\HttpSecurity;

    use Daniel\Origins\Annotations\Inject;
    use Daniel\Origins\Middleware;
    use Daniel\Origins\Request;
    use Exception;
    use Override;

    class HttpSecurityMiddleware extends Middleware{

        #[Inject]
        private HttpSecurityConfigurar $httpManager;

        #[Override]
        public function onPerrequest(Request $req) : void{
            $requestPath = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
            $requestMethod = $_SERVER['REQUEST_METHOD'];
            foreach($this->httpManager->getREQUESTS() as $r) { 
                $routeSecurity = $r->getRoute();
                if(strpos($routeSecurity, "/**") !== false){
                    $routePrefix = rtrim($routeSecurity, '/**');
                    if($routePrefix === ""){
                        $routePrefix = "/";
                    }
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

            if(!$this->httpManager->ispublic()){
                try{
                    $environment = $this->httpManager->getDefaultEnvaroment() ?? "";
                }catch(\Throwable $th){
                    $environment = $this->httpManager->getDefaultEnvaroment() ?? "";
                }
                $userDatails = SecurityContext::getContext();

                if($this->httpManager->getSessionPolice() === SessionPolice::STATELESS){
                    $_SESSION["SessionPolice"] = SessionPolice::STATELESS;
                }else{
                    $_SESSION["SessionPolice"] = SessionPolice::STATEFULL;
                }

                try {
                    $userEnv = $userDatails->getEnvironment();
                } catch (\Throwable $th) {
                    $userEnv = null;
                }

                if(!isset($userDatails)){
                    throw new AuthorizationException("not authorized");
                }else{
                    $roles = $this->httpManager->getDefaultRoles();
                    if(!empty($roles)){
                        if (empty(array_intersect($roles, $userDatails->getRoles()))) {
                            throw new AuthorityAuthorizationException("not authorized [not conteins permission Role]");
                        }
                    }
                }

                if($environment === ""){
                    
                }else if(!isset($userEnv)){
                    throw new EnvironmentAuthorizationException("not authorized [not conteins permission Enviroment]", 0, "", $environment);
                }else if($userEnv !== $environment){
                    throw new EnvironmentAuthorizationException("not authorized [not conteins permission Enviroment]", 0, $userDatails->getEnvironment(), $environment);
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
            try{
                $environment = $environment ?? $this->httpManager->getDefaultEnvaroment() ?? "";
            }catch(\Throwable $th){
                $environment = $this->httpManager->getDefaultEnvaroment() ?? "";
            }
            
            if($this->httpManager->getSessionPolice() === SessionPolice::STATELESS){
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
                    throw new EnvironmentAuthorizationException("not authorized [not conteins permission Enviroment]", 0, "", $environment);
                }else if($userDatails->getEnvironment() !== $environment){
                    throw new EnvironmentAuthorizationException("not authorized [not conteins permission Enviroment]", 0, $userDatails->getEnvironment(), $environment);
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
            foreach($this->httpManager->getFilters() as $r){
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
        private string $getUserEnv;
        private string $getTargetEnv;

        public function __construct($message = "Authorization Environment error", $code = 0, string $getUserEnv, string $gettargetEnv, Exception|null $previous = null)
        {
            parent::__construct($message, $code, $previous);
            $this->getUserEnv = $getUserEnv;
            $this->getTargetEnv = $gettargetEnv;
        }

        public function getUserEnvaroment(): string{
            return $this->getUserEnv;
        }

        public function getTargetEnvaroment(): string{
            return $this->getTargetEnv;
        }
    }
?>