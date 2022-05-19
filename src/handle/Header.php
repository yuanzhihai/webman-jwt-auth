<?php

namespace yzh52521\JwtAuth\handle;

class Header extends RequestToken
{
    protected $header = 'authorization';

    protected $prefix = 'bearer';

    /**
     * Attempt to parse the token from some other possible headers.
     *
     * @return string|null
     */
    protected function fromAltHeaders()
    {
        return \request()->header('HTTP_AUTHORIZATION') ?: \request()->header('REDIRECT_HTTP_AUTHORIZATION');
    }

    public function handle()
    {
        $authorization = \request()->header($this->header) ?: $this->fromAltHeaders();

        if ($authorization !== null) {
            $position = strripos($authorization, $this->prefix);

            if ($position !== false) {
                $header = substr($authorization, $position + strlen($this->prefix));
                return trim(strpos($header, ',') !== false ? strstr($header, ',', true) : $header);
            }
        }
        return null;
    }
}