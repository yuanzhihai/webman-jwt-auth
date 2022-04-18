<?php

namespace yzh52521\JwtAuth\facade;


use yzh52521\JwtAuth\Config;

/**
 * @see \yzh52521\JwtAuth\JwtAuth
 * @mixin \yzh52521\JwtAuth\JwtAuth
 * @method static token($id,$cliams) 生成 Token
 * @method static verify($token) 检测合法性
 * @method static parseToken($token) 解析 Token
 * @method static getVerifyToken() 获取验证后的Token对象
 * @method static getUser() 获取登录用户对象
 */
class JwtAuth
{
    protected static $_instance = null;

    public static function instance()
    {
        if (!static::$_instance) {
            static::$_instance = new \yzh52521\JwtAuth\JwtAuth(new Config(config('plugin.yzh52521.jwt-auth.app.jwt')));
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