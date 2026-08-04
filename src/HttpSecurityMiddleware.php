<?php
    namespace Daniel\HttpSecurity;

    use Daniel\Origins\Annotations\Inject;
    use Daniel\Origins\Middleware;
    use Daniel\Origins\Request;
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

                if($this->httpManager->getSessionPolice() === SessionPolice::STATELESS){
                    $_SESSION["SessionPolice"] = SessionPolice::STATELESS;
                }else{
                    $_SESSION["SessionPolice"] = SessionPolice::STATEFULL;
                }

                $userDatails = SecurityContext::getContext();

                try {
                    $userEnv = $userDatails->getEnvironment();
                } catch (\Throwable $th) {
                    $userEnv = null;
                }

                if(!isset($userDatails)){
                    throw new AuthorizationException("not authorized");
                }else{
                    $roles = $this->httpManager->getDefaultRoles();
                    $this->validateAuthorization($userDatails, $roles, $this->httpManager->getDefaultValidator());
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
                    if($this->isAuth($r->getRoles(), $r->getenvironment(), $r->getValidator())){
                        return true;
                    }
                    throw new AuthorizationException("not authorized ");
                }else{
                    return true;
                }
            }
            return false;
        }

        public function isAuth(array $roles, $environment, ?AuthorizationValidator $validator = null): bool{
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
            $this->validateAuthorization($userDatails, $roles, $validator);
            return true;
        }

        private function validateAuthorization(AuthContext $context, array $roles, ?AuthorizationValidator $validator): void{
            AuthorizationManager::validate($context, $roles, $validator);
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

?>
