<?php

use support\Model;

class User extends Model implements \yzh52521\JwtAuth\user\AuthorizationUserInterface
{
    public function getUserById($id)
    {
        return $this->find($id);
    }
}