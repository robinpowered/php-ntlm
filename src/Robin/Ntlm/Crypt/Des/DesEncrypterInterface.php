<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Des;

use InvalidArgumentException;
use Robin\Ntlm\Crypt\CipherMode;
use Robin\Ntlm\Crypt\Exception\CryptographicFailureException;

/**
 * An engine used to encrypt data using the DES standard algorithm.
 */
interface DesEncrypterInterface
{

    /**
     * Encrypts using the DES standard algorithm.
     *
     * @link https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
     * @link https://en.wikipedia.org/wiki/Initialization_vector
     * @param string $key The key to encrypt the data with.
     * @param string $data The data to encrypt.
     * @param int $mode The {@link CipherMode cipher mode} of operation.
     * @param string $initialization_vector The initialization vector used to
     *   encrypt the data in an unpredictable or reproducable fashion.
     * @return string The encrypted data as a binary string.
     * @throws InvalidArgumentException If the provided cipher mode isn't an
     *   available option.
     * @throws CryptographicFailureException If the encryption fails.
     */
    public function encrypt($key, $data, $mode, $initialization_vector);
}
