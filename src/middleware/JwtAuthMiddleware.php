<?php

namespace yzh52521\JwtAuth\middleware;

use Webman\MiddlewareInterface;
use Webman\Http\Response;
use Webman\Http\Request;
use yzh52521\JwtAuth\exception\JwtException;
use yzh52521\JwtAuth\handle\RequestToken;
use yzh52521\JwtAuth\facade\JwtAuth;

class JwtAuthMiddleware implements MiddlewareInterface
{

    protected $app;

    public function __construct()
    {
        $this->app = 'default';
    }

    public function process(Request $request, callable $next): Response
    {
        if ($request->method() === 'OPTIONS') {
            response('', 204);
        }
        try {
            $requestToken = new RequestToken();
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