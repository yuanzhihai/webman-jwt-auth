# webman-jwt-auth

## 安装

```shell

composer require yzh52521/webman-jwt-auth

```

## 完整配置

```php

<?php
return [
    'stores' => [
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
            'event_handler' => Event::class,
            'user_model'    => User::class
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
            'event_handler' => Event::class,
            'user_model'    => User::class
        ],
    ]
];

```

## token

* signer_key 密钥
* expires_at Token有效期（分）
* refresh_ttL 刷新有效期（分）
* signer 加密算法
* type 获取 Token 途径
* auto_refresh 开启过期自动续签
* event_handler 操作token事件
* user_model 用户模型

## Token 生成

```
public function login()
{
    //...登录判断逻辑

        $config = JwtAuth::getConfig();
    // 自动获取当前应用下的jwt配置
    return json([
        'token' => JwtAuth::token($uid, ['params1' => 1, 'params2' => 2])->toString(),
        'token_type' => $config->getType(),
        'expires_in' => $config->getExpires(),
        'refresh_in' => $config->getRefreshTTL(),
    ]);
    
    // 自定义用户模型
    return json([
        'token' => JwtAuth::token($uid, ['user_model' => CustomMember::class])->toString(),
        'token_type' => $config->getType(),
        'expires_in' => $config->getExpires(),
        'refresh_in' => $config->getRefreshTTL(),
    ]);
}
```

## Token 验证

```
public function verify()
{
       try {
            $jwt=JwtAuth::verify($token);
        } catch (JwtException $e) {
            throw new TokenInvalidException('登录校验已失效, 请重新登录', 401);
        }
        
        // 验证成功
        // 如配置用户模型文件 可获取当前用户信息
        dump(JwtAuth::getUser());
}
```


## Token 自动获取
支持以下方式自动获取

* `Header`
* `Cookie`
* `Url`

赋值方式

  | 类型 | 途径 | 标识 |
  | ----- |-----| ----- |
  | Header | Authorization | Bearer Token |
  | Cookie | Cookie| token |
  | Url | Request | token  |

## 过期自动续签
auto_refresh => true

系统检测到 Token 已过期， 会自动续期并返回以下 header 信息。

* Automatic-Renewal-Token
* Automatic-Renewal-Token-RefreshAt

前端需要接收最新 Token，下次异步请求时，携带此 Token。



