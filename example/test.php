<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/Event.php';
require __DIR__ . '/User.php';

$options = [
    'manager' => [
        //是否开启黑名单，单点登录和多点登录的注销、刷新使原token失效，必须要开启黑名单
        'blacklist_enabled'      => true,
        //黑名单缓存的前缀
        'blacklist_prefix'       => 'yzh52521',
        //黑名单的宽限时间 单位为：秒，注意：如果使用单点登录，该宽限时间无效
        'blacklist_grace_period' => 0,
    ],
    'stores'  => [
        'default' => [
            'login_type'    => 'mpo', //  登录方式，sso为单点登录，mpo为多点登录
            'signer_key'    => 'oP0qmqzHS4Vvml5a11111',
            'public_key'    => 'file://path/public.key',
            'private_key'   => 'file://path/private.key',
            'expires_at'    => 3600,
            'refresh_ttL'   => 7200,
            'leeway'        => 0,
            'signer'        => 'HS256',
            'type'          => 'Header',
            'auto_refresh'  => false,
            'iss'           => 'webman.client.tant',
            'event_handler' => Event::class,
            'user_model'    => User::class
        ]
    ]
];

$token = \yzh52521\JwtAuth\facade\JwtAuth::token(1, ['id' => 1, 'time' => time()])->toString();


// var_dump(\yzh52521\JwtAuth\facade\JwtAuth::verify($token));
// var_dump(\yzh52521\JwtAuth\facade\JwtAuth::parseToken($token));
