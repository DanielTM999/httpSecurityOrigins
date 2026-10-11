<?php
    namespace Daniel\HttpSecurity;
    use Daniel\HttpSecurity\AuthContext;
    use Daniel\HttpSecurity\Internal\ContextPersistence;

    class SecurityContext{

        public static function getContext(): ?AuthContext{
            return ContextPersistence::get();
        }

        public static function setContext(AuthContext $context){
            ContextPersistence::set($context);
        }

        public static function clearContext(){
            ContextPersistence::clear();
        }
    }
?>