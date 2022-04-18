<?php

namespace yzh52521\JwtAuth\user;

interface AuthorizationUserInterface
{
    public function getUserById($id): AuthorizationUserInterface;

    public function token(): string;
}
