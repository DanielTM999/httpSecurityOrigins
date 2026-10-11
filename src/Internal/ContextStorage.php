<?php

namespace Daniel\HttpSecurity\Internal;

interface ContextStorage
{
    public function load(): ?string;
    public function save(string $data): void;
    public function clear(): void;
}
