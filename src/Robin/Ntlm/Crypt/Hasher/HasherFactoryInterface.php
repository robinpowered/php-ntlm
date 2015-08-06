<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Hasher;

/**
 * A factory to build {@link HasherInterface hashers}.
 */
interface HasherFactoryInterface
{

    /**
     * Build a {@link HasherInterface} representing a specified algorithm.
     *
     * @param string $algorithm The {@link HasherAlgorithm} to use.
     * @return HasherInterface
     */
    public function build($algorithm);
}
