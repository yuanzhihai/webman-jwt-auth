<?php

namespace yzh52521\JwtAuth;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use DateTimeImmutable;
use Exception;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use yzh52521\JwtAuth\Exception\JwtException;
use yzh52521\JwtAuth\exception\TokenExpiredException;
use yzh52521\JwtAuth\exception\TokenInvalidException;
use yzh52521\JwtAuth\exception\TokenRefreshExpiredException;
use yzh52521\JwtAuth\support\Utils;

class Jwt
{
    /**
     * @var Config
     */
    protected $config;

    /**
     * @var Manager
     */
    protected $manager;

    /**
     * @var JwtAuth
     */
    protected $auth;

    public function __construct(JwtAuth $jwt,$config,$manager)
    {
        $this->auth    = $jwt;
        $this->config  = $config;
        $this->manager = $manager;

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
    public function make($identifier,array $claims = []): Token
    {
        $now = new DateTimeImmutable();
        if ($this->config->getLoginType() == 'mpo') {
            $uniqid = uniqid( $this->auth->getStore().':' ).":".$identifier;
        } else {
            $uniqid = $this->auth->getStore().":".$identifier;
        }
        $builder = $this->jwtConfiguration->builder()
            ->issuedBy( $this->config->getIss() )
            ->identifiedBy( $uniqid )
            ->issuedAt( $now )
            ->canOnlyBeUsedAfter( $now )
            ->expiresAt( $this->getExpiryDateTime( $now ) )
            ->relatedTo( $this->config->getSubject() )
            ->withClaim( 'store',$this->auth->getStore() );

        foreach ( $claims as $key => $value ) {
            $builder->withClaim( $key,$value );
        }

        $token = $builder->getToken( $this->jwtConfiguration->signer(),$this->jwtConfiguration->signingKey() );

        // 单点登录要把所有的以前生成的token都失效
        if ($this->config->getLoginType() == 'sso') $this->auth->blackList->addTokenBlack( $token,$this->config );

        return $token;
    }


    /**
     * 过期时间
     * @param $now
     * @return DateTimeImmutable
     */
    protected function getExpiryDateTime($now): DateTimeImmutable
    {
        $ttl = (string)$this->config->getExpires();
        return $now->modify( "+{$ttl} sec" );
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
            return $this->jwtConfiguration->parser()->parse( $token );
        } catch ( JwtException $e ) {
            throw new TokenInvalidException( 'Could not decode token: '.$e->getMessage(),$e->getCode(),$e );
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
        $this->token = $this->parseToken( $token );

        $claims = $this->token->claims();

        $jwtConfiguration = $this->getValidateConfig();

        $jwtConfiguration->setValidationConstraints(
            new SignedWith( $jwtConfiguration->signer(),$jwtConfiguration->signingKey() ),
            new IdentifiedBy( $claims->get( 'jti' ) )
        );

        $constraints = $jwtConfiguration->validationConstraints();

        if (!$jwtConfiguration->validator()->validate( $this->token,...$constraints )) {
            throw new TokenInvalidException( 'Token Signature could not be verified.',500 );
        }

        // 验证token是否存在黑名单
        if ($this->manager->getBlacklistEnabled() && $this->auth->blackList->hasTokenBlack( $claims,$this->config )) {
            throw new TokenInvalidException( 'The token is in blacklist',401 );
        }

        $leeway = $this->config->getleeway();

        if (Utils::isFuture( $claims->get( 'nbf' )->getTimestamp(),$leeway )) {
            throw new TokenInvalidException( 'Not Before (nbf) timestamp cannot be in the future',403 );
        }
        if (Utils::isFuture( $claims->get( 'iat' )->getTimestamp(),$leeway )) {
            throw new TokenInvalidException( 'Issued At (iat) timestamp cannot be in the future',403 );
        }

        if (Utils::isPast( $claims->get( 'exp' )->getTimestamp(),$leeway )) {
            if ($this->config->getAutoRefresh()) {
                if (Utils::isPast( $claims->get( 'iat' )->getTimestamp() + $this->config->getRefreshTTL(),$leeway )) {
                    $this->automaticRenewalToken();
                } else {
                    throw new TokenRefreshExpiredException( 'The token is refresh expired',402 );
                }
            }
            throw new TokenExpiredException( 'The token is expired.',401 );
        }

        return $this->claimsToArray( $claims->all() );
    }

    /**
     * claims对象转换成数组
     * @param $claims
     * @return mixed
     */
    private function claimsToArray(array $claims)
    {
        return collect( $claims )
            ->map( function ($claim) {
                if (is_a( $claim,\DateTimeImmutable::class )) {
                    return $claim->getTimestamp();
                }
                return is_object( $claim ) && method_exists( $claim,'getValue' )
                    ? $claim->getValue()
                    : $claim;
            } )
            ->toArray();
    }

    /**
     * 刷新token
     * @return Token
     */
    public function refreshToken()
    {
        try {
            $claims     = $this->token->claims()->all();
            $jti        = explode( ':',$claims['jti'] );
            $identifier = end( $jti );
            unset( $claims['iss'],$claims['iat'],$claims['nbf'],$claims['exp'],$claims['jti'],$claims['sub'] );
            return $this->make( $identifier,$claims );
        } catch ( JwtException $e ) {
            throw new JwtException( $e->getMessage(),$e->getCode(),$e->getPrevious() );
        }
    }


    /**
     * Token 自动续期
     *
     * @return mixed
     */
    public function automaticRenewalToken()
    {
        $claims = $this->token->claims()->all();

        $jti = explode( ':',$claims['jti'] );
        unset( $claims['iss'],$claims['jti'],$claims['iat'],$claims['nbf'],$claims['exp'],$claims['sub'] );

        $identifier = end( $jti );
        $token      = $this->make( $identifier,$claims );
        $refreshAt  = $this->config->getRefreshTTL();

        $this->token = $token;

        return response()->withHeaders( [
            'Access-Control-Expose-Headers'     => 'Automatic-Renewal-Token,Automatic-Renewal-Token-RefreshAt',
            'Automatic-Renewal-Token'           => $token->toString(),
            'Automatic-Renewal-Token-RefreshAt' => $refreshAt
        ] );
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

        throw new JwtException( 'Not logged in',404 );
    }
}
