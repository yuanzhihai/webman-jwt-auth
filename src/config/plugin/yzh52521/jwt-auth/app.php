<?php

return [
    'enable'  => true,
    'manager' => [
        //是否开启黑名单，单点登录和多点登录的注销、刷新使原token失效，必须要开启黑名单
        'blacklist_enabled'      => true,
        //黑名单缓存的前缀
        'blacklist_prefix'       => 'yzh52521',
        //黑名单的宽限时间 单位为：秒，注意：如果使用单点登录，该宽限时间无效
        'blacklist_grace_period' => 0,
    ],
    'stores'  => [
        // 单应用
        'default' => [
            'login_type'    => 'mpo', //  登录方式，sso为单点登录，mpo为多点登录
            'signer_key'    => 'oP0qmqzHS4Vvml5a',
            'public_key'    => 'file://path/public.key',
            'private_key'   => 'file://path/private.key',
            'expires_at'    => 3600,
            'refresh_ttL'   => 7200,
            'leeway'        => 0,
            'signer'        => 'HS256',
            'type'          => 'Header',
            'auto_refresh'  => false,
            'iss'           => 'webman.client.api',
            'event_handler' => '',
            'user_model'    => ''
        ],
        // 多应用
        'admin'   => [
            'login_type'    => 'mpo', //  登录方式，sso为单点登录，mpo为多点登录
            'signer_key'    => 'oP0qmqzHS4Vvml5a',
            'public_key'    => 'file://path/public.key',
            'private_key'   => 'file://path/private.key',
            'expires_at'    => 3600,
            'refresh_ttL'   => 7200,
            'leeway'        => 0,
            'signer'        => 'HS256',
            'type'          => 'Header',
            'auto_refresh'  => false,
            'iss'           => 'webman.client.admin',
            'event_handler' => '',
            'user_model'    => ''
        ],
    ]
];