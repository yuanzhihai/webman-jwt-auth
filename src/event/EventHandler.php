<?php

namespace yzh52521\JwtAuth\event;

use Lcobucci\JWT\Token;

interface EventHandler
{
    public function login(Token $token);

    public function logout(Token $token);
    
    public function verify(Token $token);
}
