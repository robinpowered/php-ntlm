<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Hasher;

/**
 * A factory to build {@link HasherInterface hashers} that use a cryptographic
 * secret key as part of their digest calculation, for example an HMAC hasher.
 */
interface KeyedHasherFactoryInterface
{

    /**
     * Build a {@link HasherInterface} representing a specified algorithm with a
     * specified cryptographic secret key.
     *
     * @param string $algorithm The {@link HasherAlgorithm} to use.
     * @param string $key The cryptographic key used in the hasher's digest
     *   calculation algorithm.
     * @return HasherInterface
     */
    public function build($algorithm, $key);
}
