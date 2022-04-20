<?php

namespace yzh52521\JwtAuth;

class Install
{
    const WEBMAN_PLUGIN = true;

    /**
     * @var array
     */
    protected static $pathRelation = array(
        'config/plugin/yzh52521/jwt-auth' => 'config/plugin/yzh52521/jwt-auth',
    );

    /**
     * Install
     * @return void
     */
    public static function install()
    {
        static::copyFile(__DIR__ . '/UserEvent.tpl', app_path() . '/common/event/UserEvent.php');
        static::installByRelation();
    }

    /**
     * Uninstall
     * @return void
     */
    public static function uninstall()
    {
        self::uninstallByRelation();
    }

    /**
     * installByRelation
     * @return void
     */
    public static function installByRelation()
    {
        foreach (static::$pathRelation as $source => $dest) {
            if ($pos = strrpos($dest, '/')) {
                $parent_dir = base_path() . '/' . substr($dest, 0, $pos);
                if (!is_dir($parent_dir)) {
                    mkdir($parent_dir, 0777, true);
                }
            }
            //symlink(__DIR__ . "/$source", base_path()."/$dest");
            copy_dir(__DIR__ . "/$source", base_path() . "/$dest");
            echo "Create $dest
";
        }
    }

    /**
     * uninstallByRelation
     * @return void
     */
    public static function uninstallByRelation()
    {
        foreach (static::$pathRelation as $source => $dest) {
            $path = base_path() . "/$dest";
            if (!is_dir($path) && !is_file($path)) {
                continue;
            }
            echo "Remove $dest
";
            if (is_file($path) || is_link($path)) {
                unlink($path);
                continue;
            }
            remove_dir($path);
        }
    }

    public static function copyFile($source, $destination)
    {
        if (!is_dir($source)) {
            echo("Error:the $source is not a direction!");
            return 0;
        }
        if (!is_dir($destination)) {
            if (!mkdir($destination, 0777) && !is_dir($destination)) {
                throw new \RuntimeException(sprintf('Directory "%s" was not created', $destination));
            }
        }
        $handle = dir($source);
        while ($entry = $handle->read()) {
            if (($entry !== ".") && ($entry !== "..")) {
                copy($source . "/" . $entry, $destination . "/" . $entry);
            }
        }
    }

}
