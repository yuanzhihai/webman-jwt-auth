# jwt-auth

## install
```bash

composer require yzh52521/webman-jwt-auth

```


## example

```php

<?php

$options = [
    'signer_key'    => 'oP0qmqzHS4Vvml5a',
    'public_key'    => 'file://path/public.key',
    'private_key'   => 'file://path/private.key',
    'not_before'    => 0,
    'signer'        => 'Lcobucci\JWT\Signer\Hmac\Sha256',
    'type'          => 'Header',
    'relogin_code'  => 50001,
    'refresh_code'  => 50002,
    'iss'           => 'client.tant',
    'aud'           => 'server.tant',
    'event_handler' => Event::class,
    'user_model'    => \app\common\model\User::class
];

// 用户 id
$id = 1;
// 附带参数
$cliasm = [];
$token = \yzh52521\JwtAuth\facade\JwtAuth::token($id, $cliams)->toString();

// 生成 token
var_dump($token);

// 验证 token
var_dump(\yzh52521\JwtAuth\facade\JwtAuth::verify($token));

// 验证后 token 对象
var_dump(\yzh52521\JwtAuth\facade\JwtAuth::getVerifyToken());

// 验证获取 id
var_dump(\yzh52521\JwtAuth\facade\JwtAuth::getVerifyToken()->claims()->get('jti'));

// 解析 token
var_dump(\yzh52521\JwtAuth\facade\JwtAuth::parseToken($token));

// 获取效验后的用户模型对象
var_dump(\yzh52521\JwtAuth\facade\JwtAuth::getUser());
```

