<?php

namespace yzh52521\JwtAuth;

use DateTimeInterface;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use DateTimeZone;
use DateTimeImmutable;
use Exception;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use yzh52521\JwtAuth\Exception\JwtException;
use yzh52521\JwtAuth\exception\TokenExpiredException;
use yzh52521\JwtAuth\exception\TokenInvalidException;
use yzh52521\JwtAuth\exception\TokenRefreshExpiredException;

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

    public function __construct(JwtAuth $jwt, $config)
    {
        $this->auth   = $jwt;
        $this->config = $config;

        $this->init();
    }

    protected function init()
    {
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
            ->issuedBy($this->config->getIss())
            ->identifiedBy((string)$identifier)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($this->getExpiryDateTime($now))
            ->relatedTo($this->config->getSubject())
            ->withClaim('store', $this->auth->getStore());

        foreach ($claims as $key => $value) {
            $builder->withClaim($key, $value);
        }

        return $builder->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());
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
     * @throws TokenInvalidException
     */
    public function parseToken(string $token): Token
    {
        try {
            return $this->jwtConfiguration->parser()->parse($token);
        } catch (JwtException $e) {
            throw new TokenInvalidException('Could not decode token: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * 效验 Token
     *
     * @param string $token
     * @return array
     * @throws TokenInvalidException
     */
    public function validate(string $token): array
    {
        $this->token = $this->parseToken($token);

        $jwtConfiguration = $this->getValidateConfig();

        $jwtConfiguration->setValidationConstraints(
            new SignedWith($jwtConfiguration->signer(), $jwtConfiguration->signingKey()),
        );

        $constraints = $jwtConfiguration->validationConstraints();

        if (!$jwtConfiguration->validator()->validate($this->token, ...$constraints)) {
            throw new TokenInvalidException('Token Signature could not be verified.', 500);
        }

        $now = new DateTimeImmutable();

        if (!$this->validateNotBefore($now)) {
            throw new TokenInvalidException('Not Before (nbf) timestamp cannot be in the future', 403);
        }
        if (!$this->validateIssuedAt($now)) {
            throw new TokenInvalidException('Issued At (iat) timestamp cannot be in the future', 403);
        }

        if (!$this->validateExpired()) {
            if ($this->config->getAutoRefresh()) {
                if (!$this->isRefreshExpired($now)) {
                    $this->token = $this->automaticRenewalToken();
                } else {
                    throw new TokenRefreshExpiredException('The token is refresh expired', 402);
                }
            }
            throw new TokenExpiredException('The token is expired.', 401);
        }

        return collect($this->token->claims()->all())
            ->map(function ($claim) {
                if (is_a($claim, \DateTimeImmutable::class)) {
                    return $claim->getTimestamp();
                }
                return is_object($claim) && method_exists($claim, 'getValue')
                    ? $claim->getValue()
                    : $claim;
            })
            ->toArray();
    }


    /**
     * Token 效验是否过期
     * @return bool
     */
    protected function validateExpired(): bool
    {
        $jwtConfiguration = $this->getValidateConfig();

        $jwtConfiguration->setValidationConstraints(
            new LooseValidAt(new SystemClock(new DateTimeZone(\date_default_timezone_get()))),
        );

        $constraints = $jwtConfiguration->validationConstraints();

        return $jwtConfiguration->validator()->validate($this->token, ...$constraints);
    }

    /**
     * 校验 Token 是否生效
     * @param DateTimeInterface $now
     * @return bool
     */
    protected function validateNotBefore(DateTimeInterface $now)
    {
        $nbf = $this->token->claims()->get('nbf');
        if (!$nbf) {
            return false;
        }

        $leeway = $this->config->getleeway();
        if ($leeway > 0) {
            $nbf = $nbf->modify("+{$leeway} sec");
        }
        return $now >= $nbf;

    }

    /**
     * 校验 Token 是否在签发时间内
     * @param DateTimeInterface $now
     * @return bool
     */
    protected function validateIssuedAt(DateTimeInterface $now)
    {
        $iat = $this->token->claims()->get('iat');
        if (!$iat) {
            return false;
        }

        $leeway = $this->config->getleeway();
        if ($leeway > 0) {
            $iat = $iat->modify("+{$leeway} sec");

        }
        return $now >= $iat;
    }


    /**
     * 刷新时间是否过期
     * @param DateTimeInterface $now
     * @return bool
     */
    public function isRefreshExpired(DateTimeInterface $now): bool
    {
        $iat = $this->token->claims()->get('iat');
        if (!$iat) {
            return false;
        }

        $refresh_ttl = $this->config->getRefreshTTL();
        $leeway      = $this->config->getleeway();
        if ($leeway > 0) {
            $refresh_ttl += $leeway;
        }
        $refresh_expired = $iat->modify("+{$refresh_ttl} sec");
        return $now >= $refresh_expired;
    }

    /**
     * Token 自动续期
     *
     * @return Token
     */
    public function automaticRenewalToken(): Token
    {
        $claims = $this->token->claims()->all();

        $jti = $claims['jti'];
        unset($claims['iss']);
        unset($claims['jti']);
        unset($claims['iat']);
        unset($claims['nbf']);
        unset($claims['exp']);
        unset($claims['sub']);

        $token     = $this->make($jti, $claims);
        $refreshAt = $this->config->getRefreshTTL();

        response()->withHeaders([
            'Access-Control-Expose-Headers'     => 'Automatic-Renewal-Token,Automatic-Renewal-Token-RefreshAt',
            'Automatic-Renewal-Token'           => $token->toString(),
            'Automatic-Renewal-Token-RefreshAt' => $refreshAt
        ]);
        return $token;
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

        throw new JwtException('Not logged in', 404);
    }
}
