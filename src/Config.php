<?php

namespace yzh52521\JwtAuth;

use Lcobucci\JWT\Signer\Ecdsa\Sha256 as ES256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as ES384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HS384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Key\LocalFileReference;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RS512;
use yzh52521\JwtAuth\event\EventHandler;
use yzh52521\JwtAuth\exception\JwtException;
use yzh52521\JwtAuth\exception\TokenInvalidException;

class Config
{
    /**
     * Hmac KEY
     * @var string
     */
    protected $signer_key = null;

    /**
     * Token 有效期
     * @var number
     */
    protected $expires_at = 3600;

    /**
     * Token 可刷新时长
     * @var number
     */
    protected $refresh_ttL = 7200;

    /**
     * Token 时钟偏差冗余时间  This applies to the claims `iat`, `nbf` and `exp`.
     * @var int
     */
    protected $leeway = 0;

    /**
     * Token 加密类型
     * @var \Lcobucci\JWT\Signer .
     */
    protected $signer = 'HS256';

    /**
     * Token 获取途径
     * @var string
     */
    protected $type = 'Header';

    /**
     * Token 签发者
     * @var string
     */
    protected $iss = 'client.xxx.com';


    /**
     * Token 是否自动续签
     * @var bool
     */
    protected $auto_refresh = false;


    /**
     * Token 用户模型
     * @var string
     */
    protected $user_model;

    /**
     * RSA 加密下公钥地址
     * @var string
     */
    protected $public_key = '';

    /**
     * RSA 加密下私钥地址
     * @var string
     */
    protected $private_key = '';


    /**
     * 事件回调
     * @var EventHandler
     */
    protected $event_handler;

    /**
     * 登录方式 sso为单点登录，mpo为多点登录
     * @var
     */
    protected $login_type = 'mpo';


    protected $signers = [
        'HS256' => HS256::class,
        'HS384' => HS384::class,
        'HS512' => HS512::class,
        'RS256' => RS256::class,
        'RS384' => RS384::class,
        'RS512' => RS512::class,
        'ES256' => ES256::class,
        'ES384' => ES384::class,
        'ES512' => ES512::class,
    ];

    public function __construct(array $options)
    {
        foreach ($options as $key => $value) {
            $this->$key = $value;
        }
    }

    /**
     * 获取 加密密钥
     *
     * @return \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function getHmacKey(): Key
    {
        if (empty($this->signer_key)) {
            throw new TokenInvalidException('config signer_key required.', 500);
        }

        return InMemory::base64Encoded((string)$this->signer_key);
    }

    /**
     * 获取 是否使用 RSA 加密
     *
     * @return bool
     */
    public function RSASigner()
    {
        $signer = $this->getSigner();

        return $signer instanceof Rsa;
    }

    /**
     * 获取 加密key
     *
     * @return Key
     */
    public function getSignerKey(): Key
    {
        $signer = $this->getSigner();

        if ($this->RSASigner()) {
            return $this->getPrivateKey();
        } else if ($signer instanceof Hmac) {
            return $this->getHmacKey();
        } else {
            throw new TokenInvalidException('not support.', 500);
        }
    }

    /**
     * 获取 RSA 公钥
     *
     * @return Key
     */
    public function getPublicKey(): Key
    {
        return LocalFileReference::file($this->public_key);
    }

    /**
     * 获取 RSA 私钥
     *
     * @return Key
     */
    public function getPrivateKey(): Key
    {
        return LocalFileReference::file($this->private_key);
    }

    /**
     * 获取有效果期
     *
     * @return number
     */
    public function getExpires()
    {
        return $this->expires_at;
    }

    /**
     * 获取刷新ttl
     *
     * @return string
     */
    public function getRefreshTTL()
    {
        return $this->refresh_ttL;
    }

    /**
     * 获取 leeway
     * @return int
     */
    public function getleeway()
    {
        return $this->leeway;
    }


    /**
     * 获取 subject
     * @return string
     */
    public function getSubject()
    {
        return md5(uniqid() . time() . rand(100000, 9999999));
    }

    /**
     * 获取iss
     *
     * @return string
     */
    public function getIss(): string
    {
        return $this->iss;
    }


    /**
     * 获取加密对象
     *
     * @return Signer
     */
    public function getSigner(): Signer
    {
        if (!array_key_exists($this->signer, $this->signers)) {
            throw new JWTException('The given signer could not be found');
        }
        return new $this->signers[$this->signer];
    }


    /**
     * 获取是否自动续签
     *
     * @return bool
     */
    public function getAutoRefresh(): bool
    {
        return $this->auto_refresh;
    }

    /**
     * 获取token途径
     *
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * 获取事件
     *
     * @return \yzh52521\JwtAuth\event\EventHandler|null
     */
    public function getEventHandler()
    {
        return $this->event_handler ?: null;
    }

    /**
     * 获取用户模型
     *
     * @return string|null
     */
    public function getUserModel()
    {
        return $this->user_model;
    }

    /**
     * 获取登录方式
     *
     * @return string
     */
    public function getLoginType()
    {
        return $this->login_type;
    }
}
