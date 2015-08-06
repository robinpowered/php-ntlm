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
class KeyedHasherFactory extends AbstractHasherFactory implements KeyedHasherFactoryInterface
{

    /**
     * {@inheritDoc}
     */
    public function build($algorithm, $key)
    {
        $algorithm = $this->validateSupportedAlgorithm($algorithm);

        return new HmacHasher($algorithm, $key);
    }
}
