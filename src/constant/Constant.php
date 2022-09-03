<?php
#+------------------------------------------------------------------
#| 普通的。
#+------------------------------------------------------------------
#| Author:Janmas Cromwell <janmas-cromwell@outlook.com>
#+------------------------------------------------------------------
namespace Janmas\Jwt\Constant;

class Constant
{
    public const ALL = [
        self::AUDIENCE,
        self::EXPIRATION_TIME,
        self::ID,
        self::ISSUED_AT,
        self::ISSUER,
        self::NOT_BEFORE,
        self::SUBJECT,
    ];

    public const DATE_CLAIMS = [
        self::ISSUED_AT,
        self::NOT_BEFORE,
        self::EXPIRATION_TIME,
    ];

    /**
     * Identifies the recipients that the JWT is intended for
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.3
     */
    public const AUDIENCE = 'aud';

    /**
     * Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.4
     */
    public const EXPIRATION_TIME = 'exp';

    /**
     * Provides a unique identifier for the JWT
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.7
     */
    public const ID = 'jti';

    /**
     * Identifies the time at which the JWT was issued
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.6
     */
    public const ISSUED_AT = 'iat';

    /**
     * Identifies the principal that issued the JWT
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.1
     */
    public const ISSUER = 'iss';

    /**
     * Identifies the time before which the JWT MUST NOT be accepted for processing
     *
     * https://tools.ietf.org/html/rfc7519#section-4.1.5
     */
    public const NOT_BEFORE = 'nbf';

    /**
     * Identifies the principal that is the subject of the JWT.
     *
     * https://tools.ietf.org/html/rfc7519#section-4.1.2
     */
    public const SUBJECT = 'sub';
}
