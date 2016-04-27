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
 * @deprectated NOTE! This implementation is deprecated, as it's been found to
 *   be insecure. More info: https://github.com/robinpowered/php-ntlm/issues/7
 * @todo Remove this implementation in a future version.
 */
class OpenSslRandomByteGenerator implements RandomByteGeneratorInterface
{

    /**
     * Methods
     */

    /**
     * {@inheritDoc}
     *
     * @deprectated NOTE! This implementation is deprecated, as it's been found
     *   to be insecure.
     */
    public function generate($size)
    {
        trigger_error(
            'This implementation is deprecated, as it can be insecure in some circumstances',
            E_USER_DEPRECATED
        );

        $generated = openssl_random_pseudo_bytes($size, $strong);

        if (false === $generated || strlen($generated) !== $size || false === $strong) {
            throw CryptographicFailureException::forReasonCode(
                CryptographicFailureException::CODE_FOR_RANDOM_DATA_GENERATION_FAILURE
            );
        }

        return $generated;
    }
}
