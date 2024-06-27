<?php

    namespace Daniel\HttpSecurity;
    use Daniel\Origins\Request;

    abstract class SecurityFilterChain{
        public abstract function filterPerRequest(Request $req);
    }

?>