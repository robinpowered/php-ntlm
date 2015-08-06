<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Hasher;

use InvalidArgumentException;

/**
 * A factory to build {@link HasherInterface hashers}.
 */
class HasherFactory extends AbstractHasherFactory implements HasherFactoryInterface
{

    /**
     * {@inheritDoc}
     */
    public function build($algorithm)
    {
        $algorithm = $this->validateSupportedAlgorithm($algorithm);

        return new TypedHasher($algorithm);
    }
}
