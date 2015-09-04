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
 * An engine used to encrypt data using the DES standard algorithm and
 * implemented using the PHP "openssl" extension.
 *
 * @link http://php.net/openssl
 */
class OpenSslDesEncrypter implements DesEncrypterInterface
{

    /**
     * Constants
     */

    /**
     * The default OpenSSL encryption options.
     *
     * @type int
     */
    const DEFAULT_OPENSSL_OPTIONS = OPENSSL_RAW_DATA;


    /**
     * Properties
     */

    /**
     * A map of {@link CipherMode}s to the "openssl" extension equivalents.
     */
    private static $cipher_mode_map = [
        CipherMode::CBC => 'des-cbc',
        CipherMode::CFB => 'des-cfb',
        CipherMode::ECB => 'des-ecb',
        CipherMode::OFB => 'des-ofb',
    ];

    /**
     * Whether or not to zero-byte pad the data before encrypting for some
     * cipher modes.
     *
     * @type bool
     */
    private $zero_pad;


    /**
     * Methods
     */

    /**
     * Constructor
     *
     * @param bool $zero_pad Whether or not to zero-byte pad the data before
     *   encrypting for some cipher modes.
     */
    public function __construct($zero_pad = true)
    {
        $this->zero_pad = $zero_pad;
    }

    /**
     * {@inheritDoc}
     */
    public function encrypt($key, $data, $mode, $initialization_vector)
    {
        if (isset(self::$cipher_mode_map[$mode])) {
            $mode = self::$cipher_mode_map[$mode];
        } else {
            throw new InvalidArgumentException('Unknown cipher mode "'. $mode .'"');
        }

        $options = $this->getOpenSslEncryptionOptions();

        $encrypted = openssl_encrypt($data, $mode, $key, $options, $initialization_vector);

        if (false === $encrypted) {
            throw CryptographicFailureException::forReasonCode(
                CryptographicFailureException::CODE_FOR_ENCRYPTION_FAILURE
            );
        }

        return $encrypted;
    }

    /**
     * Gets the OpenSSL encryption options.
     *
     * @return int The options to use in an OpenSSL encryption call.
     */
    private function getOpenSslEncryptionOptions()
    {
        $options = self::DEFAULT_OPENSSL_OPTIONS;

        if ($this->zero_pad) {
            $options = $options | OPENSSL_ZERO_PADDING;
        }

        return $options;
    }
}
