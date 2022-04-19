<?php

namespace yzh52521\JwtAuth;

use yzh52521\JwtAuth\event\EventHandler;
use yzh52521\JwtAuth\exception\InvalidArgumentException;

class Event
{
    /**
     * @var EventHandler
     */
    protected $handle;

    public function __construct($handle = null)
    {
        if ($handle) {
            $class = new $handle;
            if ($class instanceof EventHandler) {
                $this->handle = $class;
            } else {
                throw new InvalidArgumentException('must be implements yzh52521\JwtAuth\event\EventHandler');
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
