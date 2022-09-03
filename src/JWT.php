<?php
#+------------------------------------------------------------------
#| 普通的。
#+------------------------------------------------------------------
#| Author:Janmas Cromwell <janmas-cromwell@outlook.com>
#+------------------------------------------------------------------
namespace Janmas\Jwt;

use encryption\Encryption;
use Janmas\Jwt\Builder\Builder;
use Janmas\Jwt\Signer\Signer;
use Janmas\Jwt\Utils\Helpers;

final class JWT
{

    public function builder(string $secret = '')
    {
        $secret = $secret ?? Helpers::randomStr();
        return new Builder($secret);
    }

    /**
     * @param string $token
     * @param string $secret 私钥
     * @param string $iss 签发机构
     * @param string $aud 使用者
     * @return bool|mixed
     * @throws \Exception
     */
    public function verify(string $token, string $secret = '', string $iss = '', string $aud = '')
    {
        try {
            list($originalHeader, $originalBody, $signature) = explode('.', $token);
        } catch
        (\Exception $e) {
            return false;
        }
        $header = Helpers::base64Decode($originalHeader);
        $header = json_decode($header, true);
        if (isset($header['Encrypt-Body']) && $header['Encrypt-Body']) {
            $body = Encryption::decrypt($originalBody);
        } else {
            $body = $originalBody;

        }
        $signerClass = '\Janmas\Jwt\Signer\\' . $header['alg'];
        if (!class_exists($signerClass)) {
            throw new \Exception('不支持的的加密方式');
        }
        /**
         * @var Signer $signer
         */
        $signer = new $signerClass;
        if ($signer->encrypt($originalHeader . '.' . $originalBody, $secret) != Helpers::base64Decode($signature)) {
            throw new \Exception('验签失败');
        }
        $body = Helpers::base64Decode($body);
        $body = json_decode($body, true);

        if (!empty($aud) && $body['aud'] != $aud) {
            throw new \Exception('令牌用户异常');
        }


        if (!empty($iss) && $body['iss'] != $iss) {
            throw new \Exception('签发结构错误');
        }

        if ($body['iat'] > time()) {
            throw new \Exception('签发时间异常');
        }

        if (!empty($body['nbf']) && $body['nbf'] < time()) {
            throw new \Exception('令牌暂时不可用');
        }

        if ($body['exp'] < time()) {
            throw new \Exception('已经过期，请重新签发');
        }
        return $body;
    }


}
