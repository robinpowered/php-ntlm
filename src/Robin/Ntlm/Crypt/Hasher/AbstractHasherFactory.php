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
 * A base for factory hashers to build on top of.
 *
 * Does not force implementation of either factory type.
 */
abstract class AbstractHasherFactory
{

    /**
     * Properties
     */

    /**
     * The algorithms supported by this factory/platform.
     *
     * @type []string
     */
    private $supported_algorithms;


    /**
     * Methods
     */

    /**
     * Create the factory instance by detecting what algorithms are supported.
     *
     * @return static
     */
    public static function createWithDetectedSupportedAlgorithms()
    {
        return new static(
            hash_algos()
        );
    }

    /**
     * Constructor
     *
     * @param array $supported_algorithms The algorithms supported.
     */
    public function __construct(array $supported_algorithms)
    {
        $this->supported_algorithms = $supported_algorithms;
    }

    /**
     * Gets the algorithms supported by this factory/platform.
     *
     * @return []string
     */
    public function getSupportedAlgorithms()
    {
        return $this->supported_algorithms;
    }

    /**
     * Validates that a given algorithm is supported.
     *
     * @param string $algorithm The {@link HasherAlgorithm} to validate.
     * @return string The validated algorithm.
     */
    protected function validateSupportedAlgorithm($algorithm)
    {
        if (!in_array($algorithm, $this->supported_algorithms, true)) {
            throw new InvalidArgumentException(
                sprintf(
                    'Algorithm "%s" not supported',
                    $algorithm
                )
            );
        }

        return $algorithm;
    }
}
