<?php

namespace yzh52521\JwtAuth\handle;

class Cookie extends RequestToken
{
    public function handle()
    {
        return request()->cookie('token');
    }
}