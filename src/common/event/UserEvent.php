<?php

namespace app\common\event;

use Lcobucci\JWT\Token;

class UserEvent implements \yzh52521\JwtAuth\event\EventHandler
{

    protected $app;

    public function __construct($app)
    {
        $this->app = $app;
    }


    public function login(Token $token)
    {
        // todo
    }

    public function logout(Token $token)
    {
        // todo
    }

    public function verify(Token $token)
    {
        // todo
    }
}