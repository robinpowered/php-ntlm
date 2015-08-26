<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Random;

use UnexpectedValueException;

/**
 * An generator used to generate cryptographically secure random bytes.
 *
 * Useful for generating random binary strings to be used as a "nonce" or as an
 * initialization vector.
 */
interface RandomByteGeneratorInterface
{

    /**
     * Generates cryptographically secure random bytes.
     *
     * @param int $size The length, in bytes, of the string to generate.
     * @return string The randomly generated binary string.
     * @throws UnexpectedValueException If the generation fails.
     */
    public function generate($size);
}
