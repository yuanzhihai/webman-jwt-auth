<?php

use Lcobucci\JWT\Token;

require_once __DIR__ . '/../vendor/autoload.php';

class Event implements \yzh52521\JwtAuth\EventHandler
{
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
