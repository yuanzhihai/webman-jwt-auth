# webman-jwt-auth

## 说明

> 目前支持如下三大类型加密方式：RSA,HASH,DSA。再各分256、384、512位。 默认是HS256，即hash 256位加密。

> 需要修改加密方式，请修改参数：signer，参数选项：

* HS256
  备注：hash 256位

* HS384
  备注：hash 384位

* HS512
  备注：hash 512位

* RS256
  备注：rsa 256位

* RS384
  备注：rsa 384位

* RS512
  备注：rsa 512位

* ES256
  备注：dsa 256位

* ES384
  备注：dsa 384位

* ES512
  备注：dsa 512位

> 重要：RSA和DSA 都是非对称加密方式，除了修改参数signer外，需要配置：PUBLIC_KEY、PRIVATE_KEY两个参数， 这两个参数是密钥文件路径

## 安装

```shell

composer require yzh52521/webman-jwt-auth

```

## 完整配置

```php

<?php
return [
      'manager' => [
        //是否开启黑名单，单点登录和多点登录的注销、刷新使原token失效，必须要开启黑名单
        'blacklist_enabled'      => true,
        //黑名单缓存的前缀
        'blacklist_prefix'       => 'yzh52521',
        //黑名单的宽限时间 单位为：秒，注意：如果使用单点登录，该宽限时间无效
        'blacklist_grace_period' => 0,
      ],
       'stores' => [
        // 单应用
        'default' => [
            'login_type'    => 'mpo', 
            'signer_key'    => 'oP0qmqzHS4Vvml5a',
            'public_key'    => 'file://path/public.key',
            'private_key'   => 'file://path/private.key',
            'expires_at'    => 3600,
            'refresh_ttL'   => 7200,
            'leeway'        => 0,
            'signer'        =>'HS256',
            'type'          => 'Header',
            'auto_refresh'  => false,
            'iss'           => 'webman.client.api',
            'event_handler' => Event::class,
            'user_model'    => User::class
        ],
        // 多应用
        'admin'   => [
            'login_type'    => 'mpo', 
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
            'event_handler' => Event::class,
            'user_model'    => User::class
        ],
    ]
];

```

## 说明：

> 支持多应用单点登录、多应用多点登录、多应用支持注销 token(token会失效)、支持多应用刷新 token

> 多应用单点登录：在该应用配置下只会有一个 token 生效，一旦刷新 token ，前面生成的 token 都会失效，一般以用户 id 来做区分

> 多应用多点登录：在该配置应用下token 不做限制，一旦刷新 token ，则当前配置应用的 token 会失效

> 注意：使用多应用单点登录或者多应用多点登录时，必须要开启黑名单，使用 redis 缓存。如果不开启黑名单，无法使 token 失效，生成的
> token 会在有效时间内都可以使用(未更换证书或者 secret )。

> 多应用单点登录原理：JWT 有七个默认字段供选择。单点登录主要用到 jti 默认字段，jti 字段的值默认为缓存到redis中的key(
> 该key的生成为应用名称+存储的用户id)，这个key的值会存一个签发时间，token检测会根据这个时间来跟token原有的签发时间对比，如果token原有时间小于等于redis存的时间，则认为无效

> 多应用多点登录原理：多点登录跟单点登录差不多，唯一不同的是jti的值不是应用名称+用户id，而是一个唯一字符串，每次调用
> refreshToken 来刷新 token 或者调用 logout 注销 token 会默认把请求头中的 token 加入到黑名单，而不会影响到别的 token

> token 不做限制原理：token 不做限制，在 token 有效的时间内都能使用，你只要把配置文件中的 blacklist_enabled 设置为 false
> 即可，即为关闭黑名单功能

## token

* login_type 登录方式,sso为单点登录，mpo为多点登录
* signer_key 密钥
* expires_at Token有效期（单位秒）
* refresh_ttL 刷新有效期（单位秒）
* leeway 时钟偏差冗余时间，单位秒。建议这个余地应该不大于几分钟。
* signer 加密算法
* type 获取 Token 途径
* auto_refresh 开启过期自动续签
* event_handler token用户事件
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

## Token 刷新

> 注意：必须验证通过才可以刷新Token 获取新Token

```
$jwt =JwtAuth::refresh();
```

## Token 注销

注销后Token就失效了（用户退出）

```
  JwtAuth::logout($token);
```

## Token 获取过期时间

```
  JwtAuth::getTokenExpirationTime($token=null);
```


## Token 移除黑名单token(指定某个)

```
  JwtAuth::removeBlackList($token);
```

## Token 移除所有黑名单Token

```
  JwtAuth::clearBlackList();
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


> 备注 ：多应用 默认是在应用目录里使用 
> 跨应用 生成token 验证token 解析token 等使用如下

```
    实例化 参数应用名  
    $JwtAuth =new yzh52521\JwtAuth\JwtAuth('default'); 
    
    //生成token
    $config = $JwtAuth->getConfig();
    // 自动获取当前应用下的jwt配置
    return json([
        'token' => $JwtAuth->token($uid, ['params1' => 1, 'params2' => 2])->toString(),
        'token_type' => $config->getType(),
        'expires_in' => $config->getExpires(),
        'refresh_in' => $config->getRefreshTTL(),
    ]);
    
      //验证token
       $JwtAuth =new yzh52521\JwtAuth\JwtAuth('default'); 
       try {
           $data= $JwtAuth->verify($token);
           dump($data);
        } catch (JwtException $e) {
            throw new TokenInvalidException('登录校验已失效, 请重新登录', 401);
        }
        //解析token
        $JwtAuth =new yzh52521\JwtAuth\JwtAuth('default'); 
        
        $JwtAuth->parseToken($token);
        $JwtAuth->getVerifyToken();
        
        
 
 
```



