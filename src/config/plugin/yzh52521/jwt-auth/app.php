<?php

return [
    'enable' => true,
    'jwt'    => [
        'signer_key'    => 'oP0qmqzHS4Vvml5a',
        'public_key'    => 'file://path/public.key',
        'private_key'   => 'file://path/private.key',
        'not_before'    => 0,
        'expires_at'    => 3600,
        'refresh_ttL'   => 7200,
        'signer'        => 'Lcobucci\JWT\Signer\Hmac\Sha256',
        'type'          => 'Header',
        'login_code'    => 50001,
        'refresh_code'  => 50002,
        'auto_refresh'  => 0,
        'iss'           => 'client.tant',
        'aud'           => 'server.tant',
        'event_handler' => Event::class,
        'user_model'    => \app\model\User::class
    ]
];