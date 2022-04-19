<?php

return [
    'enable' => true,
    'jwt'    => [
        'signer_key'    => 'oP0qmqzHS4Vvml5a',
        'public_key'    => 'file://path/public.key',
        'private_key'   => 'file://path/private.key',
        'expires_at'    => 3600,
        'refresh_ttL'   => 7200,
        'signer'        => 'Lcobucci\JWT\Signer\Hmac\Sha256',//算法类型 HS256、HS384、HS512、RS256、RS384、RS512、ES256、ES384、ES512
        'type'          => 'Header',
        'login_code'    => 50001,
        'refresh_code'  => 50002,
        'auto_refresh'  => 0,
        'iss'           => 'webman.client.com',
        'event_handler' => Event::class,
        'user_model'    => User::class
    ]
];