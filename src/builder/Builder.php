<?php
#+------------------------------------------------------------------
#| 普通的。
#+------------------------------------------------------------------
#| Author:Janmas Cromwell <janmas-cromwell@outlook.com>
#+------------------------------------------------------------------
namespace Janmas\Jwt\Builder;

use encryption\Encryption;
use Janmas\Jwt\Constant\Constant;
use Janmas\Jwt\Signer\Signer;
use Janmas\Jwt\Utils\Helpers;

class Builder
{
    /**
     * 发行人
     * @var string
     */
    protected $issuer;

    /**
     * 使用人
     * @var string
     */
    protected $audience;

    /**
     * ID
     * @var
     */
    protected $id;

    /**
     * 发行时间
     * @var
     */
    protected $issuedAt;

    /**
     * 生效时间
     * @var
     */
    protected $entryAt;

    /**
     * 私钥
     * @var
     */
    protected $secret;

    protected $payload = [];

    public function __construct(string $secret = '')
    {
        $this->secret = $secret;
    }

    /**
     * 唯一标识
     * @param string $id
     * @return Builder
     */
    public function id(string $id)
    {
        $this->appendPayload(Constant::ID, $id);
        return $this;
    }

    /**
     * 接收方
     * @param string $audience
     * @return Builder
     */
    public function audience(string $audience)
    {
        $this->appendPayload(Constant::AUDIENCE, $audience);
        return $this;
    }

    /**
     * 发布者
     * @param string $issuser
     * @return $this
     */
    public function issuer(string $issuser)
    {
        $this->appendPayload(Constant::ISSUER, $issuser);
        return $this;
    }

    /**
     * 发布时间
     * @param int $issuedAt
     * @return $this
     */
    public function issuedAt(int $issuedAt)
    {
        $this->appendPayload(Constant::ISSUED_AT, $issuedAt);
        return $this;
    }

    /**
     * 生效时间
     * @param int $time
     * @return $this
     */
    public function notBefore(int $time)
    {
        $this->appendPayload(Constant::NOT_BEFORE, $time);
        return $this;
    }

    /**
     * 过期时间
     * @param int $time
     * @return $this
     */
    public function expiration(int $time)
    {
        $this->appendPayload(Constant::EXPIRATION_TIME, $time);
        return $this;
    }

    /**
     * 设置主题
     * @param array $payload
     * @return $this
     */
    public function subject(string $subject)
    {
        $this->appendPayload(Constant::SUBJECT, $subject);
        return $this;
    }

    /**
     * 设置需要的参数
     * @param array $claims
     * @return $this
     */
    public function claims(array $claims)
    {
        foreach ($claims as $key => $value) {
            $this->appendPayload($key, $value);
        }
        return $this;
    }

    /**
     * 设置需要的参数
     * @param string $name
     * @param string $value
     * @return $this
     */
    public function withClaims(string $name, string $value)
    {
        $this->appendPayload($name, $value);
        return $this;
    }

    /**
     * 签名
     * @param Signer $signer
     * @param bool $encryptPayload 是否加密payload
     * @param int $offset payload偏移量
     * @return string
     */
    public function sign(Signer $signer, bool $encryptPayload = false, int $offset = 0)
    {
        if (!isset($this->payload[Constant::ID])) throw new \Exception('缺少唯一标识jti');
        $options = [];
        if ($encryptPayload) {
            $options = ['Encrypt-Body' => $encryptPayload];
        }
        $header = $signer->header($options);
        $payload = Helpers::formatPayload($this->payload);
        if ($encryptPayload) {
            $payload = Encryption::encrypt($payload, $offset <= 0 ? null : $offset);
        }
        $signature = $signer->encrypt($header . '.' . $payload, $this->secret);
        $signature = Helpers::base64Encode($signature);

        return $header . '.' . $payload . '.' . $signature;
    }

    protected function appendPayload(string $name, $value)
    {
        $this->payload[$name] = $value;
    }

}
