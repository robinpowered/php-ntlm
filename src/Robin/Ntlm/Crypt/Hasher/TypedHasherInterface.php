<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Hasher;

/**
 * {@inheritDoc}
 *
 * Allows for identifying the "type" of hashing algorithm used.
 */
interface TypedHasherInterface extends HasherInterface
{

    /**
     * Gets the algorithm of the hasher.
     *
     * @return string Maps to a {@link HasherAlgorithm} value.
     */
    public function getAlgorithm();
}
