<?php

namespace yzh52521\JwtAuth;

use Webman\App;
use Webman\MiddlewareInterface;
use Webman\Http\Response;
use Webman\Http\Request;
use yzh52521\JwtAuth\exception\JwtException;
use yzh52521\JwtAuth\handle\RequestToken;
use yzh52521\JwtAuth\facade\JwtAuth;

class JwtAuthMiddware implements MiddlewareInterface
{
    /**
     * @param App
     */
    protected $app;

    public function __construct(App $app)
    {
        $this->app = $app;
    }

    public function process(Request $request, callable $next): Response
    {
        if ($request->method() === 'OPTIONS') {
            response('', 204);
        }
        try {
            $requestToken = new RequestToken($this->app);
            $handel       = JwtAuth::getConfig($this->app)->getType();
            $token        = $requestToken->get($handel);
            JwtAuth::verify($token);
            $request->user = JwtAuth::getUser();
            return $next($request);
        } catch (JwtException $e) {
            return response($e->getMessage(), 401);
        }
    }
}