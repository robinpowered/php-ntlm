<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Random;

use Robin\Ntlm\Crypt\Exception\CryptographicFailureException;

/**
 * A cryptographically secure random byte generator implemented using the PHP
 * "openssl" extension.
 *
 * @link http://php.net/openssl
 */
class OpenSslRandomByteGenerator implements RandomByteGeneratorInterface
{

    /**
     * Methods
     */

    /**
     * {@inheritDoc}
     */
    public function generate($size)
    {
        $generated = openssl_random_pseudo_bytes($size, $strong);

        if (false === $generated || strlen($generated) !== $size || false === $strong) {
            throw CryptographicFailureException::forReasonCode(
                CryptographicFailureException::CODE_FOR_RANDOM_DATA_GENERATION_FAILURE
            );
        }

        return $generated;
    }
}
