<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Des;

use SplFixedArray;

/**
 * {@inheritDoc}
 *
 * Provides an abstraction for common NTLM required operations, such as key
 * expansion and normalization.
 */
abstract class AbstractDesEncrypter implements DesEncrypterInterface
{

    /**
     * Properties
     */

    /**
     * Whether or not to expand and normalize the key before encrypting.
     *
     * @type bool
     */
    private $expand_and_normalize_keys;


    /**
     * Methods
     */

    /**
     * Constructor
     *
     * @param bool $expand_and_normalize_keys Whether or not to expand and
     *   normalize the key before encrypting.
     */
    public function __construct($expand_and_normalize_keys = true)
    {
        $this->expand_and_normalize_keys = $expand_and_normalize_keys;
    }

    /**
     * Process a key for DES encryption.
     *
     * Optionally performs an expansion and normalization process to the key.
     *
     * @param string $raw_key The raw key.
     * @return string The processed key.
     */
    protected function processKey($raw_key)
    {
        $key = $raw_key;

        if ($this->expand_and_normalize_keys) {
            $key = self::expand56BitKeyTo64BitKey($key, true);
        }

        return $key;
    }

    /**
     * Expands a 56-bit key to a full 64-bit key for DES encryption.
     *
     * @link http://php.net/manual/en/ref.hash.php#84587 Implementation basis.
     * @link https://github.com/jclulow/node-smbhash/blob/edc48e2b/lib/common.js
     *   Inspired by Joshua Clulow's work.
     * @param string $string_key The 56-bit key to expand.
     * @param bool $set_parity Whether or not to set parity for each byte.
     * @return string The expanded key.
     */
    private static function expand56BitKeyTo64BitKey($string_key, $set_parity = true)
    {
        $byte_array_56 = new SplFixedArray(7);
        $byte_array_64 = new SplFixedArray(8);
        $key_64bit = '';

        // Get the byte value of each ASCII character in the string
        for ($i = 0; $i < $byte_array_56->getSize(); $i++) {
            $byte_array_56[$i] = isset($string_key[$i]) ? ord($string_key[$i]) : 0;
        }

        $byte_array_64[0] = $byte_array_56[0] & 254;
        $byte_array_64[1] = ($byte_array_56[0] << 7) | ($byte_array_56[1] >> 1);
        $byte_array_64[2] = ($byte_array_56[1] << 6) | ($byte_array_56[2] >> 2);
        $byte_array_64[3] = ($byte_array_56[2] << 5) | ($byte_array_56[3] >> 3);
        $byte_array_64[4] = ($byte_array_56[3] << 4) | ($byte_array_56[4] >> 4);
        $byte_array_64[5] = ($byte_array_56[4] << 3) | ($byte_array_56[5] >> 5);
        $byte_array_64[6] = ($byte_array_56[5] << 2) | ($byte_array_56[6] >> 6);
        $byte_array_64[7] = $byte_array_56[6] << 1;

        foreach ($byte_array_64 as $byte_val) {
            // Optionally set parity for each byte
            $byte_val = $set_parity ? self::setParityBit($byte_val) : $byte_val;

            $key_64bit .= chr($byte_val);
        }

        return $key_64bit;
    }

    /**
     * Set an odd parity bit for a given byte, in least-significant position.
     *
     * @link https://github.com/jclulow/node-smbhash/blob/edc48e2b/lib/common.js
     *   Implementation basis.
     * @param int $byte An 8-bit byte value.
     * @return int An 8-bit byte value.
     */
    private static function setParityBit($byte)
    {
        $parity = 1;

        for ($i = 1; $i < 8; $i++) {
            $parity = ($parity + (($byte >> $i) & 1)) %2;
        }

        $byte = $byte | ($parity & 1);

        return $byte;
    }
}
