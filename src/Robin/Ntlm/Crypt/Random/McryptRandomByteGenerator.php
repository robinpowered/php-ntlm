<?php
/**
 * Robin NTLM
 *
 * @copyright 2016 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Random;

use Robin\Ntlm\Crypt\Exception\CryptographicFailureException;
use UnexpectedValueException;

/**
 * A cryptographically secure random byte generator implemented using the PHP
 * "mcrypt" extension.
 *
 * @link http://php.net/mcrypt
 * @deprectated NOTE! This implementation is deprecated, as the mcrypt library
 *   is abandoned. More info: https://github.com/robinpowered/php-ntlm/pull/1
 * @todo Remove this implementation in a future version.
 */
class McryptRandomByteGenerator implements RandomByteGeneratorInterface
{

    /**
     * Constants
     */

    /**
     * The default source of randomness.
     *
     * @type int
     */
    const DEFAULT_SOURCE = MCRYPT_DEV_URANDOM;


    /**
     * Properties
     */

    /**
     * The `mcrypt_create_iv` compatible source.
     *
     * @link http://php.net/manual/en/mcrypt.constants.php
     * @type int
     */
    private $source = self::DEFAULT_SOURCE;


    /**
     * Methods
     */

    /**
     * Constructor
     *
     * @link http://php.net/manual/en/mcrypt.constants.php
     * @param int $source The `mcrypt_create_iv` compatible source of
     *   cryptographically secure randomness. Defaults to self::DEFAULT_SOURCE.
     */
    public function __construct($source = self::DEFAULT_SOURCE)
    {
        $this->source = $source;
    }

    /**
     * {@inheritDoc}
     *
     * @deprectated NOTE! This implementation is deprecated, as the mcrypt
     *   library is abandoned.
     */
    public function generate($size)
    {
        trigger_error(
            'This implementation is deprecated, as the mcrypt library is abandoned',
            E_USER_DEPRECATED
        );

        $generated = mcrypt_create_iv($size, $this->source);

        if (false === $generated || strlen($generated) !== $size) {
            throw CryptographicFailureException::forReasonCode(
                CryptographicFailureException::CODE_FOR_RANDOM_DATA_GENERATION_FAILURE
            );
        }

        return $generated;
    }
}
