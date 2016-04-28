<?php
/**
 * Robin NTLM
 *
 * @copyright 2016 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Random;

use Error;
use Exception;
use Robin\Ntlm\Crypt\Exception\CryptographicFailureException;

/**
 * A cryptographically secure random byte generator implemented using the native
 * PHP CSPRNG functions.
 *
 * @link http://php.net/csprng
 */
class NativeRandomByteGenerator implements RandomByteGeneratorInterface
{

    /**
     * Methods
     */

    /**
     * {@inheritDoc}
     */
    public function generate($size)
    {
        try {
            $generated = random_bytes($size);
        } catch (Error $e) {
            // PHP 7+ will throw an `Error`. Catch here to make sure that we don't accidentally catch a polyfilled
            // `Error` from a polyfill library, such as https://github.com/paragonie/random_compat
            throw $e;
        } catch (Exception $e) {
            throw CryptographicFailureException::forReasonCode(
                CryptographicFailureException::CODE_FOR_RANDOM_DATA_GENERATION_FAILURE,
                $e
            );
        }

        return $generated;
    }
}
