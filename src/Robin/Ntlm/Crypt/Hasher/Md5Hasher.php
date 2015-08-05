<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Hasher;

/**
 * A cryptographic hasher implemented using the "MD5" algorithm.
 */
class Md5Hasher extends AbstractHasher
{

    /**
     * Constants
     */

    /**
     * The string identifier of the algorithm used by PHP's hash extension.
     *
     * @type string
     */
    const HASH_EXT_ALGORITHM_IDENTIFIER = 'md5';


    /**
     * Methods
     */

    /**
     * {@inheritDoc}
     */
    protected function getAlgorithmIdentifier()
    {
        return static::HASH_EXT_ALGORITHM_IDENTIFIER;
    }
}
