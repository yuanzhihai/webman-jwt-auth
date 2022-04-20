<?php

return [
    'enable' => true,

    'stores' => [
        // 单应用
        'default' => [
            'signer_key'    => 'oP0qmqzHS4Vvml5a',
            'public_key'    => 'file://path/public.key',
            'private_key'   => 'file://path/private.key',
            'expires_at'    => 3600,
            'refresh_ttL'   => 7200,
            'signer'        => \Lcobucci\JWT\Signer\Hmac\Sha256::class,
            'type'          => 'Header',
            'auto_refresh'  => false,
            'iss'           => 'webman.client.api',
            'event_handler' => '',
            'user_model'    => ''
        ],
        // 多应用
        'admin'   => [
            'signer_key'    => 'oP0qmqzHS4Vvml5a',
            'public_key'    => 'file://path/public.key',
            'private_key'   => 'file://path/private.key',
            'expires_at'    => 3600,
            'refresh_ttL'   => 7200,
            'signer'        => \Lcobucci\JWT\Signer\Hmac\Sha256::class,
            'type'          => 'Header',
            'auto_refresh'  => false,
            'iss'           => 'webman.client.admin',
            'event_handler' => '',
            'user_model'    => ''
        ],
    ]
];