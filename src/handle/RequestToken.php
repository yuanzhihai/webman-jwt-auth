<?php

namespace yzh52521\JwtAuth\handle;

use Webman\App;
use yzh52521\JwtAuth\exception\JwtException;

class RequestToken
{
    protected $handles = ['Header', 'Url', 'Cookie'];

    /**
     * @var string|null
     */
    protected $token;

    /**
     * @var App
     */
    protected $app;

    public function __construct(App $app)
    {
        $this->app = $app;
    }

    /**
     * 获取请求Token.
     *
     * @param string|array $handle
     *
     * @return string
     */
    public function get($handle): string
    {
        if (is_string($handle)) {
            $handles = explode('|', $handle);
        }

        foreach ($handles as $handle) {
            if (in_array($handle, $this->handles)) {
                $namespace = '\\yzh52521\\JwtAuth\\handle\\' . $handle;
                $token     = (new $namespace($this->app))->handle();
                if ($token) {
                    $this->token = $token;
                    break;
                }
            } else {
                throw new JwtException('不支持此方式获取.', 500);
            }
        }

        if (!$this->token) {
            throw new JwtException('获取Token失败.', 500);
        }

        return $this->token;
    }
}