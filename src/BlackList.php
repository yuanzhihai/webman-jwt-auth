<?php

namespace yzh52521\JwtAuth;

use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\RegisteredClaims;
use support\Redis;
use yzh52521\JwtAuth\support\Utils;

class BlackList
{
    protected $prefix;

    public function __construct(protected JwtAuth $auth,protected Manager $manager)
    {
        $this->prefix  = $manager->getBlacklistPrefix();
    }

    /**
     * 把token加入到黑名单中
     * @param Plain $token
     * @param Config $config
     * @return bool
     */
    public function addTokenBlack(Plain $token,Config $config): bool
    {
        $claims = $token->claims();
        if ($this->manager->getBlacklistEnabled()) {
            $cacheKey = $this->getCacheKey( $claims->get( 'jti' ) );
            $iatTime              = Utils::getTimeByTokenTime( $claims->get( RegisteredClaims::ISSUED_AT ) );
            if ($config->getLoginType() == 'mpo') {
                $blacklistGracePeriod = $this->manager->getBlacklistGracePeriod();
                $validUntil           = $iatTime->addSeconds( $blacklistGracePeriod )->getTimestamp();
            } else {
                /**
                 * 为什么要取当前的时间戳？
                 * 是为了在单点登录下，让这个时间前当前用户生成的token都失效，可以把这个用户在多个端都踢下线
                 */
                $validUntil           = Utils::now()->subSeconds( 1 )->getTimestamp();
            }
            /**
             * 缓存时间取当前时间跟jwt过期时间的差值，单位秒
             */
            $tokenCacheTime = $this->getTokenCacheTime( $claims );
            if ($tokenCacheTime > 0) {
                return Redis::setEx( $cacheKey,$tokenCacheTime,serialize( ['valid_until' => $validUntil] ) );
            }
        }
        return false;
    }

    /**
     * 获取token缓存时间，根据token的过期时间跟当前时间的差值来做缓存时间
     *
     * @param  $claims
     * @return int
     */
    private function getTokenCacheTime($claims): int
    {
        $expTime = Utils::getTimeByTokenTime( $claims->get( RegisteredClaims::EXPIRATION_TIME ) );
        $nowTime = Utils::now();
        // 优化，如果当前时间大于过期时间，则证明这个jwt token已经失效了，没有必要缓存了
        // 如果当前时间小于等于过期时间，则缓存时间为两个的差值
        if ($nowTime->lte( $expTime )) {
            // 加1秒防止临界时间缓存问题
            return $expTime->diffInSeconds( $nowTime ) + 1;
        }

        return 0;
    }


    /**
     * 判断token是否已经加入黑名单
     * @param $claims
     * @return bool
     */
    public function hasTokenBlack($claims,Config $config): bool
    {
        $cacheKey = $this->getCacheKey( $claims->get( 'jti' ) );
        if ($this->manager->getBlacklistEnabled()) {
            $cacheValue = Redis::get( $cacheKey );
            if ($cacheValue == null) {
                return true;
            }
            $val = unserialize( $cacheValue );
            if ($config->getLoginType() == 'mpo') {
                return !empty( $val['valid_until'] ) && !Utils::isFuture( $val['valid_until'] );
            }
            if ($config->getLoginType() == 'sso') {
                $iatTime = Utils::getTimeByTokenTime( $claims->get( RegisteredClaims::ISSUED_AT ) )->getTimestamp();;
                if (!empty( $iatTime ) && !empty( $val['valid_until'] )) {
                    // 当前token的签发时间小于等于缓存的签发时间，则证明当前token无效
                    return $iatTime <= $val['valid_until'];
                }
            }
        }
        return false;
    }

    /**
     * 黑名单移除token
     * @param $token
     * @return bool
     */
    public function remove($token): bool
    {
        $claims = $token->claims();
        $key    = $this->prefix.':'.$claims->get( 'jti' );
        return Redis::del( $key );
    }

    /**
     * 移除所有的token缓存
     * @return bool
     */
    public function clear(): bool
    {
        $keys = Redis::keys( "{$this->prefix}:*" );
        return Redis::del( $keys );
    }

    /**
     * @param string $jti
     * @return string
     */
    private function getCacheKey(string $jti): string
    {
        return "{$this->prefix}:".$jti;
    }

}
