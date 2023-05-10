<?php

namespace yzh52521\JwtAuth\middleware;

use Webman\MiddlewareInterface;
use Webman\Http\Response;
use Webman\Http\Request;
use yzh52521\JwtAuth\exception\JwtException;
use yzh52521\JwtAuth\handle\RequestToken;

class JwtAuthMiddleware implements MiddlewareInterface
{

    public function process(Request $request,callable $next): Response
    {
        if ($request->method() === 'OPTIONS') {
            response( '',204 );
        }
        if ($route = $request->route) {
            $store = $route->param( 'store' );
        }
        $store   = $store ?? ( \request()->app === '' ? 'default' : \request()->app );
        $JwtAuth = new \yzh52521\JwtAuth\JwtAuth( $store );
        try {
            $requestToken = new RequestToken();
            $jwtConfig    = $JwtAuth->getConfig();
            $handel       = $jwtConfig->getType();
            $token        = $requestToken->get( $handel );
            $JwtAuth->verify( $token );
            $request->jwt = $JwtAuth;
            $jwtConfig->getUserModel() && $request->user = $JwtAuth->getUser();
            return $next( $request );
        } catch ( JwtException $e ) {
            throw new JwtException( $e->getMessage(),$e->getCode() );
        }
    }
}
