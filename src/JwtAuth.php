<?php

namespace yzh52521\JwtAuth;

use Lcobucci\JWT\Token;
use yzh52521\JwtAuth\event\EventHandler;
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
    protected $event;

    /**
     * @var User
     */
    protected User $user;

    public function __construct(Config $config, EventHandler $event = null)
    {
        $this->config = $config;
        $this->event  = $event;
        $this->init();
    }

    protected function init()
    {
        $this->jwt = new Jwt($this);

        $this->initUser();
    }

    protected function initUser()
    {
        if ($model = $this->config->getUserModel()) {
            $this->user = new User($model);
        }
    }

    /**
     * 获取 Token 配置
     */
    public function getConfig(): Config
    {
        return $this->config;
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

        throw new TokenInvalidException('jwt.user_model required');
    }
}
