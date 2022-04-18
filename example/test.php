<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/Event.php';

$options = [
    'signer_key'    => 'oP0qmqzHS4Vvml5a11111',
    'public_key'    => 'file://path/public.key',
    'private_key'   => 'file://path/private.key',
    'not_before'    => 0,
    'expires_at'    => 3600,
    'refresh_ttL'   => 7200,
    'signer'        => 'Lcobucci\JWT\Signer\Hmac\Sha256',
    'type'          => 'Header',
    'relogin_code'  => 50001,
    'refresh_code'  => 50002,
    'auto_refresh'  => 0,
    'iss'           => 'client.tant',
    'aud'           => 'server.tant',
    'event_handler' => Event::class,
    'user_model'    => User::class
];

$id    = 1;
$token = \yzh52521\JwtAuth\facade\JwtAuth::token($id, ['time' => time()])->toString();
// var_dump($auth->parseToken($token));
