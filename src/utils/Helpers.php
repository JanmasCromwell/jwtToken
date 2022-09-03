<?php
#+------------------------------------------------------------------
#| 普通的。
#+------------------------------------------------------------------
#| Author:Janmas Cromwell <janmas-cromwell@outlook.com>
#+------------------------------------------------------------------
namespace Janmas\Jwt\Utils;

use Janmas\Jwt\Constant\Constant;

class Helpers
{
    static function randomStr(int $length = 16, $hasDoc = false)
    {
        $str = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        if ($hasDoc) {
            $str .= '!@#$%^&*_+';
        }

        $strlen = strlen($str) - 1;
        $randomStr = '';
        $i = 0;
        for ($i; $i < $length; $i++) {
            $randomStr[$i] = $str[rand(0, $strlen)];
        }

        return $randomStr;
    }

    /**
     * 格式化的base64混淆
     * @return void
     */
    static function base64Encode($data): string
    {
        $base64 = base64_encode($data);
        return str_replace('=', '', strtr($base64, '+/', '-_'));
    }

    static function base64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $addlen = 4 - $remainder;
            $input .= str_repeat('=', $addlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    static function formatPayload(array $data): string
    {
        $keys = array_keys($data);
        $diff = array_diff(Constant::DATE_CLAIMS, $keys);
        foreach ($diff as $value) {
            $data[$value] = time();
        }
        $diff = array_diff(Constant::ALL, $keys);
        foreach ($diff as $value) {
            $data[$value] = '';
        }
        return self::base64Encode(json_encode($data));
    }
}
