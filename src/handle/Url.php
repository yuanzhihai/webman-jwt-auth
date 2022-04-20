<?php

namespace yzh52521\JwtAuth\handle;

class Url extends RequestToken
{
    public function handle()
    {
        return request()->get('token');
    }
}