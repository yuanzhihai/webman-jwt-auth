<?php

namespace yzh52521\JwtAuth;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use DateTimeZone;
use DateTimeImmutable;
use Exception;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;

class Jwt
{
    /**
     * @var Config
     */
    protected $config;

    /**
     * @var JwtAuth
     */
    protected $auth;

    public function __construct(JwtAuth $jwt)
    {
        $this->auth = $jwt;

        $this->init();
    }

    protected function init()
    {
        $this->config = $this->auth->getConfig();
        $this->initJwtConfiguration();
    }

    /**
     * 加密配置
     *
     * @return void
     */
    protected function initJwtConfiguration()
    {
        $this->jwtConfiguration = Configuration::forSymmetricSigner(
            $this->config->getSigner(),
            $this->config->getSignerKey()
        );
    }

    /**
     * 生成 Token
     * @param $identifier
     * @param array $claims
     * @return $token
     */
    public function make($identifier, array $claims = []): Token
    {
        $now     = new DateTimeImmutable();
        $builder = $this->jwtConfiguration->builder()
            ->permittedFor($this->config->getAud())
            ->issuedBy($this->config->getIss())
            ->identifiedBy((string)$identifier)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($this->getNotBeforeDateTime($now))
            ->expiresAt($this->getExpiryDateTime($now))
            ->relatedTo((string)$identifier);

        foreach ($claims as $key => $value) {
            $builder->withClaim($key, $value);
        }

        return $builder->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());
    }

    /**
     * Not Before
     * @param $now
     * @return DateTimeImmutable
     */
    protected function getNotBeforeDateTime($now): DateTimeImmutable
    {
        $ttl = (string)$this->config->getNotBefore();
        return $now->modify("+{$ttl} sec");
    }

    /**
     * 过期时间
     * @param $now
     * @return DateTimeImmutable
     */
    protected function getExpiryDateTime($now): DateTimeImmutable
    {
        $ttl = (string)$this->config->getExpires();
        return $now->modify("+{$ttl} sec");
    }

    /**
     * 解析 Token
     * @param string $token
     * @return Token
     */
    public function parseToken(string $token): Token
    {
        return $this->jwtConfiguration->parser()->parse($token);
    }

    /**
     * 效验 Token
     *
     * @param string $token
     * @return bool
     */
    public function validate(string $token): bool
    {
        $this->token = $this->parseToken($token);

        $jwtConfiguration = $this->getValidateConfig();

        $jwtConfiguration->setValidationConstraints(
            new SignedWith($jwtConfiguration->signer(), $jwtConfiguration->signingKey()),
            new LooseValidAt(new SystemClock(new DateTimeZone(\date_default_timezone_get()))),
        );

        $constraints = $jwtConfiguration->validationConstraints();

        return $jwtConfiguration->validator()->validate($this->token, ...$constraints);
    }

    /**
     * 获取检验配置
     */
    protected function getValidateConfig()
    {
        return Configuration::forSymmetricSigner(
            $this->config->getSigner(),
            $this->config->RSASigner() ? $this->config->getPublicKey() : $this->config->getHmacKey()
        );
    }

    /**
     * 验证成功后的Token
     *
     * @return Token
     * @throws Exception
     */
    public function getVerifyToken()
    {
        if ($this->token) {
            return $this->token;
        }

        throw new Exception('Not logged in');
    }
}
