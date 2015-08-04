<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Random;

use UnexpectedValueException;

/**
 * A cryptographically secure random byte generator implemented using the PHP
 * "mcrypt" extension.
 *
 * @link http://php.net/mcrypt
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
     */
    public function generate($size)
    {
        $generated = mcrypt_create_iv($size, $this->source);

        if (false === $generated || strlen($generated) !== $size) {
            throw new UnexpectedValueException('Failed to generate random bytes.');
        }

        return $generated;
    }
}
