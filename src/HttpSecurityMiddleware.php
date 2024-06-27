<?php

    use Daniel\Origins\DependencyManager;
    use Daniel\Origins\HttpMethod;
    use Daniel\Origins\Inject;
    use Daniel\Origins\Middleware;
    use Daniel\Origins\Request;

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
                if($this->httpManager->getSessionPolice() === SessionPolice::STATELESS){
                    echo "auth";
                    return;
                }
            }
        }

        private function authAction($routeSecurity, $requestPath, $r, Request $req,bool $verifiMethod = false){
            if($routeSecurity === $requestPath || $verifiMethod){
                $this->applyFilters($req);
                if($r->getNeedAuth()){
                    if($this->isAuth($r->getRoles())){
                        return true;
                    }
                    throw new Exception("not authorized ");
                }else{
                    return true;
                }
            }
            return false;
        }

        public function isAuth($roles): bool{
            if($this->httpManager->getSessionPolice() === SessionPolice::STATELESS){
                $_SESSION["SessionPolice"] = SessionPolice::STATELESS;
            }else{
                $_SESSION["SessionPolice"] = SessionPolice::STATEFULL;
            }

            $userDatails = SecurityContext::getContext();

            if(!isset($userDatails)){
                return false;
            }

            if(!empty($roles)){
                foreach($roles as $role){
                    foreach($userDatails->getRoles() as $roleUser){
                        if($role === $roleUser){
                            return true;
                        }
                    }
                }
                throw new Exception("not authorized [not conteins permission Role]");
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

?>