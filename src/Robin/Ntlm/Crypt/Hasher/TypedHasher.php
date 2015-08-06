<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Hasher;

use UnexpectedValueException;

/**
 * {@inheritDoc}
 */
class TypedHasher extends AbstractTypedHasher
{

    /**
     * Constructor
     *
     * @param string $algorithm The {@link HasherAlgorithm} to use.
     */
    public function __construct($algorithm)
    {
        $context = hash_init($algorithm);

        parent::__construct($context, $algorithm);
    }
}
