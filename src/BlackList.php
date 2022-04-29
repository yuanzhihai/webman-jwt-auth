<?php

namespace yzh52521\JwtAuth;

use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\RegisteredClaims;
use Psr\SimpleCache\CacheInterface;
use support\Cache;
use Xmo\JWTAuth\Util\TimeUtil;
use yzh52521\JwtAuth\support\Utils;

class BlackList
{
    protected $prefix;
    /**
     * @var CacheInterface
     */
    public $cache;

    /**
     * @var Manager
     */
    protected $manager;

    /**
     * @var JwtAuth
     */
    protected $auth;

    public function __construct(JwtAuth $jwt, Manager $manager)
    {
        $this->cache   = Cache::class;
        $this->auth    = $jwt;
        $this->manager = $manager;
        $this->prefix  = $manager->getBlacklistPrefix();
    }

    /**
     * 把token加入到黑名单中
     * @param Plain $token
     * @param Config $config
     * @return bool
     */
    public function addTokenBlack(Plain $token, Config $config): bool
    {
        $claims = $token->claims();
        if ($this->manager->getBlacklistEnabled()) {
            $cacheKey = $this->getCacheKey($claims->get('jti'));
            if ($config->getLoginType() == 'mpo') {
                $blacklistGracePeriod = $this->manager->getBlacklistGracePeriod();
                $iatTime              = $claims->get(RegisteredClaims::ISSUED_AT);
                $validUntil           = $iatTime->addSeconds($blacklistGracePeriod)->getTimestamp();
            } else {
                /**
                 * 为什么要取当前的时间戳？
                 * 是为了在单点登录下，让这个时间前当前用户生成的token都失效，可以把这个用户在多个端都踢下线
                 */
                $validUntil = Utils::now()->subSeconds(1)->getTimestamp();
            }
            $tokenCacheTime = $this->getTokenCacheTime($claims);
            return $this->cache::set($cacheKey, ['valid_until' => $validUntil], $tokenCacheTime);
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
        $expTime = Utils::getTimeByTokenTime($claims->get(RegisteredClaims::EXPIRATION_TIME));
        $nowTime = Utils::now();
        // 优化，如果当前时间大于过期时间，则证明这个jwt token已经失效了，没有必要缓存了
        // 如果当前时间小于等于过期时间，则缓存时间为两个的差值
        if ($nowTime->lte($expTime)) {
            // 加1秒防止临界时间缓存问题
            return $expTime->diffInSeconds($nowTime) + 1;
        }

        return 0;
    }


    /**
     * 判断token是否已经加入黑名单
     * @param $claims
     * @return bool
     */
    public function hasTokenBlack($claims, Config $config)
    {
        $cacheKey = $this->getCacheKey($claims->get('jti'));
        if ($this->manager->getBlacklistEnabled() && $config->getLoginType() == 'mpo') {
            $val = $this->cache::get($cacheKey);
            return !empty($val['valid_until']) && !Utils::isFuture($val['valid_until']);
        }

        if ($this->manager->getBlacklistEnabled() && $config->getLoginType() == 'sso') {
            $val = $this->cache::get($cacheKey);
            // 这里为什么要大于等于0，因为在刷新token时，缓存时间跟签发时间可能一致，详细请看刷新token方法
            if (!is_null($claims->get('iat')) && !empty($val['valid_until'])) {
                $isFuture = ($claims->get('iat')->getTimestamp() - $val['valid_until']) >= 0;
            } else {
                $isFuture = false;
            }
            // check whether the expiry + grace has past
            return !$isFuture;
        }
        return false;
    }

    /**
     * 黑名单移除token
     * @param $token
     * @return bool
     */
    public function remove($token)
    {
        $claims = $token->claims();
        $key    = $this->prefix . '_' . $claims->get('jti');
        return $this->cache::delete($key);
    }

    /**
     * 移除所有的token缓存
     * @return bool
     */
    public function clear()
    {
        return $this->cache::delete("{$this->prefix}.*");
    }

    /**
     * @param string $jti
     * @return string
     */
    private function getCacheKey(string $jti)
    {
        return "{$this->prefix}_" . $jti;
    }

}
