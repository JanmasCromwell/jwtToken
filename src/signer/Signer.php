<?php
#+------------------------------------------------------------------
#| 普通的。
#+------------------------------------------------------------------
#| Author:Janmas Cromwell <janmas-cromwell@outlook.com>
#+------------------------------------------------------------------
namespace Janmas\Jwt\Signer;

use Janmas\Jwt\Utils\Helpers;

abstract class Signer
{
    /**
     * 用于JWTheader加密
     */
    protected $mark = [
        'typ' => '',
        'alg' => ''
    ];

    abstract public function encrypt(string $payload, string $key);

    abstract public function decrypt($content, $sign, $publicKey);

    public function header(array $option = [])
    {
        return Helpers::base64Encode(json_encode(array_merge($option, $this->mark)));
    }

    protected function loadKey($key)
    {
        if (is_file($key)) {
            return file_get_contents($key);
        } else if (strpos($key, 'file://') !== false) {
            $handle = fopen($key, 'r');
            fseek($handle, 0, SEEK_END);
            $size = (int)ftell($handle);
            $content = fread($handle, $size);
            fclose($handle);
            return $content;
        } else if (is_string($key)) {
            return "-----BEGIN RSA PRIVATE KEY-----\n" .
                wordwrap($key, 64, "\n", true) .
                "\n-----END RSA PRIVATE KEY-----";
        }
        return '';
    }
}
