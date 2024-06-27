<?php

    namespace Daniel\HttpSecurity;

    interface AuthContext{
        function getUser():string;
        function getPassword():string;
        function getRoles():array;
    }

?>