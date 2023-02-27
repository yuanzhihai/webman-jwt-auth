<?php

namespace yzh52521\JwtAuth;

use yzh52521\JwtAuth\event\EventHandler;
use yzh52521\JwtAuth\exception\TokenInvalidException;

class Event
{

    public function __construct(protected $handle = null)
    {
        if ($handle) {
            $class = new $handle;
            if ($class instanceof EventHandler) {
                $this->handle = $class;
            } else {
                throw new TokenInvalidException('must be implements yzh52521\JwtAuth\event\EventHandler',500);
            }
        }
    }

    public function __call($name, $arguments)
    {
        if ($this->handle) {
            call_user_func_array([$this->handle, $name], $arguments);
        }
    }
}
