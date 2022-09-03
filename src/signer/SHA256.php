<?php
#+------------------------------------------------------------------
#| 普通的。
#+------------------------------------------------------------------
#| Author:Janmas Cromwell <janmas-cromwell@outlook.com>
#+------------------------------------------------------------------
namespace Janmas\Jwt\Signer;

class SHA256 extends Signer
{
    protected $mark = [
        'typ' => 'JWT',
        'alg' => 'SHA256'
    ];

    public function encrypt(string $payload, string $key)
    {
        $key = $this->loadKey($key);
        $key = openssl_get_privatekey($key);

        openssl_sign($payload, $signature, $key, OPENSSL_ALGO_SHA256);
        openssl_free_key($key);
        return $signature;
    }

    public function decrypt($content, $sign, $key)
    {

        $key = $this->loadKey($key);

        $key = openssl_get_publickey($key);
        $ok = openssl_verify($content, base64_decode($sign), $key, 'SHA256');
        openssl_free_key($key);
        return $ok;
    }
}
