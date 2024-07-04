<?php
    namespace Daniel\HttpSecurity;
    use Daniel\HttpSecurity\AuthContext;

    class SecurityContext{   
        private static ?AuthContext $context = null;

        public static function getContext(): ?AuthContext{
            if(!isset(self::$context)){
                self::$context=null;
            }
            if (isset($_SESSION["SessionPolice"]) && $_SESSION["SessionPolice"] !== SessionPolice::STATELESS) {
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
            if(isset($_SESSION["SessionPolice"])){
                if($_SESSION["SessionPolice"] === SessionPolice::STATELESS){
                    self::$context = $context;
                }else{
                    $_SESSION["Securitycontext"] = serialize($context);
                }
            }else{
                self::$context = $context;
            }
        }

        public static function clearContext(){
            if(isset($_SESSION["SessionPolice"])){
                if($_SESSION["SessionPolice"] === SessionPolice::STATELESS){
                    self::$context = null;
                }else{
                    unset($_SESSION["Securitycontext"]);
                }
            }else{
                self::$context = null;
            }
        }
    }
?>