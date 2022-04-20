<?php

namespace yzh52521\JwtAuth\handle;

class Header extends RequestToken
{
    public function handle()
    {
        $authorization = request()->header('authorization');

        $token = '';
        if ($authorization && preg_match('/Bearer\s*(\S+)\b/i', $authorization, $matches)) {
            $token = $matches[1];
        }
        if (!$token) {
            return;
        }

        return $token;
    }
}