<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Hasher;

/**
 * Constant definitions of hashing algorithms.
 *
 * The values of each constant map to the names returned by the
 * {@link http://php.net/manual/en/function.hash-algos.php `hash_algos()`}
 * function.
 */
class HasherAlgorithm
{

    /**
     * @type string
     */
    const MD2 = 'md2';

    /**
     * @type string
     */
    const MD4 = 'md4';

    /**
     * @type string
     */
    const MD5 = 'md5';

    /**
     * @type string
     */
    const SHA1 = 'sha1';

    /**
     * @type string
     */
    const SHA224 = 'sha224';

    /**
     * @type string
     */
    const SHA256 = 'sha256';

    /**
     * @type string
     */
    const SHA384 = 'sha384';

    /**
     * @type string
     */
    const SHA512 = 'sha512';

    /**
     * @type string
     */
    const RIPEMD128 = 'ripemd128';

    /**
     * @type string
     */
    const RIPEMD160 = 'ripemd160';

    /**
     * @type string
     */
    const RIPEMD256 = 'ripemd256';

    /**
     * @type string
     */
    const RIPEMD320 = 'ripemd320';

    /**
     * @type string
     */
    const WHIRLPOOL = 'whirlpool';

    /**
     * @type string
     */
    const TIGER128_3 = 'tiger128,3';

    /**
     * @type string
     */
    const TIGER160_3 = 'tiger160,3';

    /**
     * @type string
     */
    const TIGER192_3 = 'tiger192,3';

    /**
     * @type string
     */
    const TIGER128_4 = 'tiger128,4';

    /**
     * @type string
     */
    const TIGER160_4 = 'tiger160,4';

    /**
     * @type string
     */
    const TIGER192_4 = 'tiger192,4';

    /**
     * @type string
     */
    const SNEFRU = 'snefru';

    /**
     * @type string
     */
    const SNEFRU256 = 'snefru256';

    /**
     * @type string
     */
    const GOST = 'gost';

    /**
     * @type string
     */
    const GOST_CRYPTO = 'gost-crypto';

    /**
     * @type string
     */
    const ADLER32 = 'adler32';

    /**
     * @type string
     */
    const CRC32 = 'crc32';

    /**
     * @type string
     */
    const CRC32B = 'crc32b';

    /**
     * @type string
     */
    const FNV132 = 'fnv132';

    /**
     * @type string
     */
    const FNV1A32 = 'fnv1a32';

    /**
     * @type string
     */
    const FNV164 = 'fnv164';

    /**
     * @type string
     */
    const FNV1A64 = 'fnv1a64';

    /**
     * @type string
     */
    const JOAAT = 'joaat';

    /**
     * @type string
     */
    const HAVAL128_3 = 'haval128,3';

    /**
     * @type string
     */
    const HAVAL160_3 = 'haval160,3';

    /**
     * @type string
     */
    const HAVAL192_3 = 'haval192,3';

    /**
     * @type string
     */
    const HAVAL224_3 = 'haval224,3';

    /**
     * @type string
     */
    const HAVAL256_3 = 'haval256,3';

    /**
     * @type string
     */
    const HAVAL128_4 = 'haval128,4';

    /**
     * @type string
     */
    const HAVAL160_4 = 'haval160,4';

    /**
     * @type string
     */
    const HAVAL192_4 = 'haval192,4';

    /**
     * @type string
     */
    const HAVAL224_4 = 'haval224,4';

    /**
     * @type string
     */
    const HAVAL256_4 = 'haval256,4';

    /**
     * @type string
     */
    const HAVAL128_5 = 'haval128,5';

    /**
     * @type string
     */
    const HAVAL160_5 = 'haval160,5';

    /**
     * @type string
     */
    const HAVAL192_5 = 'haval192,5';

    /**
     * @type string
     */
    const HAVAL224_5 = 'haval224,5';

    /**
     * @type string
     */
    const HAVAL256_5 = 'haval256,5';
}
