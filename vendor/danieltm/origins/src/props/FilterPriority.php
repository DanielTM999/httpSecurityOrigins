<?php


    #[Attribute(Attribute::TARGET_CLASS|Attribute::TARGET_CLASS_CONSTANT)]
    class FilterPriority{
        public function __construct(public int $exception) {

        }
    }

?>