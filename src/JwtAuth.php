<?php

namespace yzh52521\JwtAuth;

use Lcobucci\JWT\Token;
use yzh52521\JwtAuth\exception\TokenInvalidException;
use yzh52521\JwtAuth\support\Utils;
use yzh52521\JwtAuth\user\AuthorizationUserInterface;

class JwtAuth
{
    /**
     * @var Config
     */
    protected Config $config;

    protected $manager;

    /**
     * @var Jwt
     */
    protected Jwt $jwt;

    /**
     * @var Event
     */
    protected Event $event;

    /**
     * @param string $store
     */
    protected string $store;

    /**
     * @param $string $defaultStore
     */
    protected string $defaultStore = 'default';

    /**
     * @var User
     */
    protected User $user;

    /**
     * @var BlackList
     */
    public $blackList;

    public function __construct($store = null)
    {
        $this->config  = $this->getConfig($store);
        $this->manager = $this->getManager();

        $this->init();
    }

    protected function init()
    {
        $this->jwt = new Jwt($this, $this->config, $this->manager);

        $this->blackList = new BlackList($this, $this->manager);

        $this->initUser();

        $this->initEvent();

    }

    protected function initUser()
    {
        if ($model = $this->config->getUserModel()) {
            $this->user = new User($model);
        }
    }

    protected function initEvent()
    {
        if ($event = $this->config->getEventHandler()) {
            $this->event = new Event($event);
        }
    }


    /**
     * 获取应用配置
     * @return Config
     */
    public function getConfig($store = null): Config
    {
        if (!$store) {
            $store = $this->getDefaultApp();
        }
        $options = config('plugin.yzh52521.jwt-auth.app.stores.' . $store);
        return new Config($options);
    }

    /**
     * 获取黑名单配置
     * @return Manager
     */
    public function getManager(): Manager
    {
        $options = config('plugin.yzh52521.jwt-auth.app.manager') ?? [];
        return new Manager($options);
    }

    /**
     * 获取应用
     * @return string
     */
    public function getStore(): string
    {
        return $this->store ?? $this->getDefaultApp();
    }

    /**
     * 获取默认应用
     * @return string
     */
    protected function getDefaultApp(): string
    {
        return $this->defaultStore;
    }


    /**
     * 生成 Token
     * @param $id
     * @param array $cliams
     * @return Token
     */
    public function token($id, array $cliams = []): Token
    {
        $token = $this->jwt->make($id, $cliams);

        $this->event && $this->event->login($token);

        return $token;
    }

    /**
     * 检测合法性
     * @param $token
     * @return array
     */
    public function verify($token): array
    {
        $jwt = $this->jwt->validate($token);

        $this->event && $this->event->verify($this->parseToken($token));

        return $jwt;
    }

    /**
     * 刷新token
     * @return Token
     */
    public function refreshToken()
    {
        return $this->jwt->refreshToken();
    }


    /**
     * 退出让token失效
     * @param $token
     * @return bool
     */
    public function logout($token)
    {
        $this->blackList->addTokenBlack($this->parseToken($token), $this->config);

        $this->event && $this->event->logout($this->parseToken($token));

        return true;
    }

    /**
     * 解析 Token
     * @param $token
     * @return Token
     */
    public function parseToken($token): Token
    {
        return $this->jwt->parseToken($token);
    }

    /**
     * 获取验证后的Token对象
     * @return Token
     */
    public function getVerifyToken(): Token
    {
        return $this->jwt->getVerifyToken();
    }


    /**
     * 移除黑名单Token
     * @param $token
     * @return bool
     */
    public function removeBlackList($token): bool
    {
        $this->blackList->remove($this->parseToken($token));

        return true;
    }

    /**
     * 移除所有的token缓存
     * @return bool
     */
    public function clearBlackList(): bool
    {
        $this->blackList->clear();

        return true;
    }


    /**
     * 获取token动态有效时间
     * @param string|null $token
     * @return int
     */
    public function getTokenExpirationTime(string $token = null): int
    {
        $now = Utils::now()->getTimestamp();
        if (empty($token)) $token = $this->getVerifyToken();
        $exp = $this->parseToken($token)->claims()->get('exp');
        return $exp->getTimestamp() - $now;

    }

    /**
     * 获取登录用户对象
     *
     * @return AuthorizationUserInterface|null
     */
    public function getUser()
    {
        if ($this->user) {
            return $this->user->get($this->jwt);
        }

        throw new TokenInvalidException('jwt.user_model required', 500);
    }
}
