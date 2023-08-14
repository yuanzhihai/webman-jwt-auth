<?php

namespace yzh52521\JwtAuth\support;

use Carbon\Carbon;

class Utils
{
    /**
     * Get the Carbon instance for the current time.
     *
     * @return \Carbon\Carbon
     */
    public static function now()
    {
        return Carbon::now(date_default_timezone_get());
    }

    /**
     * Get the Carbon instance for the timestamp.
     *
     * @param int $timestamp
     *
     * @return \Carbon\Carbon
     */
    public static function timestamp($timestamp)
    {
        return Carbon::createFromTimestamp($timestamp, date_default_timezone_get());
    }

    /**
     * Checks if a timestamp is in the past.
     *
     * @param int $timestamp
     * @param int $leeway
     *
     * @return bool
     */
    public static function isPast($timestamp, $leeway = 0)
    {
        $timestamp = static::timestamp($timestamp);

        return $leeway > 0
            ? $timestamp->addSeconds($leeway)->isPast()
            : $timestamp->isPast();
    }

    /**
     * Checks if a timestamp is in the future.
     *
     * @param int $timestamp
     * @param int $leeway
     *
     * @return bool
     */
    public static function isFuture($timestamp, $leeway = 0)
    {
        $timestamp = static::timestamp($timestamp);

        return $leeway > 0
            ? $timestamp->subSeconds($leeway)->isFuture()
            : $timestamp->isFuture();
    }

    /**
     *
     * @param $tokenTime
     * @return Carbon
     */
    public static function getTimeByTokenTime($tokenTime): Carbon
    {
        $timestamp = $tokenTime;
        if (!is_numeric($tokenTime)) {
            $timestamp = $tokenTime->getTimestamp();
        }

        return self::timestamp($timestamp);
    }
}