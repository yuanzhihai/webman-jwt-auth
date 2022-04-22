<?php

namespace yzh52521\JwtAuth;

use Lcobucci\JWT\Token;
use yzh52521\JwtAuth\exception\TokenInvalidException;
use yzh52521\JwtAuth\user\AuthorizationUserInterface;

class JwtAuth
{
    /**
     * @var Config
     */
    protected Config $config;

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

    public function __construct($store = null)
    {
        $this->config = $this->getConfig($store);
        $this->init();
    }

    protected function init()
    {
        $this->jwt = new Jwt($this, $this->config);

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

        $this->jwt->validatePayload();

        $this->event && $this->event->verify($this->parseToken($token));

        return $jwt;
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
