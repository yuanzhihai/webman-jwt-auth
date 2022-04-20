<?php

namespace app\common\event;

use Lcobucci\JWT\Token;
use Webman\App;

class UserEvent implements \yzh52521\JwtAuth\event\EventHandler
{

    /**
     * @var App
     */
    protected $app;

    public function __construct(App $app)
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