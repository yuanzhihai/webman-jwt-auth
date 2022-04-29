<?php

namespace yzh52521\JwtAuth;

class Manager
{
    protected $blacklist_prefix = 'yzh52521';
    protected $blacklist_enabled = false;
    protected $blacklist_grace_period = 0;

    public function __construct(array $options = [])
    {
        if (!empty($options)) {
            foreach ($options as $key => $value) {
                $this->$key = $value;
            }
        }
    }

    public function getBlacklistPrefix(): string
    {
        return $this->blacklist_prefix;
    }

    public function getBlacklistEnabled(): bool
    {
        return $this->blacklist_enabled;
    }

    public function getBlacklistGracePeriod(): int
    {
        return $this->blacklist_grace_period;
    }

}
