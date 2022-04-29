<?php

namespace yzh52521\JwtAuth\facade;


/**
 * @see \yzh52521\JwtAuth\JwtAuth
 * @mixin \yzh52521\JwtAuth\JwtAuth
 * @method static token($id, array $cliams) 生成 Token
 * @method static verify($token) 检测Token合法性
 * @method static refreshToken() 刷新Token 返回新Token
 * @method static logout($token) 注销Token
 * @method static parseToken($token) 解析 Token
 * @method static getVerifyToken() 获取验证后的Token对象
 * @method static getUser() 获取登录用户对象
 * @method static getTokenExpirationTime($token = null) 获取Token动态有效时间
 * @method static getConfig($store = null) 获取 Token 配置
 */
class JwtAuth
{
    protected static $_instance = null;

    public static function instance()
    {
        if (!static::$_instance) {
            $app               = request()->app ?? null;
            static::$_instance = new \yzh52521\JwtAuth\JwtAuth($app);
        }
        return static::$_instance;
    }


    /**
     * @param $name
     * @param $arguments
     * @return mixed
     */
    public static function __callStatic($name, $arguments)
    {
        return static::instance()->{$name}(... $arguments);
    }
}