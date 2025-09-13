<?php
    namespace Daniel\HttpSecurity;
    use Daniel\HttpSecurity\AuthContext;

    class SecurityContext{   
        private static ?AuthContext $context = null;

        public static function getContext(): ?AuthContext{
            $sessionPolice = $_SESSION["SessionPolice"] ?? SessionPolice::STATELESS;
            if(!isset(self::$context)){
                self::$context=null;
            }
            if ($sessionPolice !== SessionPolice::STATELESS) {
                if (isset($_SESSION["Securitycontext"])) {
                    return unserialize($_SESSION["Securitycontext"]);
                }else{
                    return self::$context;
                }
            } else {
                return self::$context;
            }
        }

        public static function setContext(AuthContext $context){
            $sessionPolice = $_SESSION["SessionPolice"] ?? SessionPolice::STATELESS;
            if($sessionPolice === SessionPolice::STATELESS){
                self::$context = $context;
            }else{
                $_SESSION["Securitycontext"] = serialize($context);
            }
        }

        public static function clearContext(){
            self::$context = null;
            unset($_SESSION["Securitycontext"]);
        }
    }
?>