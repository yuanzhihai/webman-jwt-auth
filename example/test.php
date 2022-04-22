<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/Event.php';
require __DIR__ . '/User.php';

$options = [
    'stores' => [
        'default' => [
            'signer_key'    => 'oP0qmqzHS4Vvml5a11111',
            'public_key'    => 'file://path/public.key',
            'private_key'   => 'file://path/private.key',
            'expires_at'    => 3600,
            'refresh_ttL'   => 7200,
            'signer'        => 'Sha256',
            'type'          => 'Header',
            'auto_refresh'  => false,
            'iss'           => 'client.tant',
            'event_handler' => Event::class,
            'user_model'    => User::class
        ]
    ]
];

$token = \yzh52521\JwtAuth\facade\JwtAuth::token(1, ['id' => 1, 'time' => time()])->toString();


 // var_dump(\yzh52521\JwtAuth\facade\JwtAuth::verify($token));
// var_dump(\yzh52521\JwtAuth\facade\JwtAuth::parseToken($token));
