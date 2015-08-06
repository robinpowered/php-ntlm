<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Hasher;

use UnexpectedValueException;

/**
 * {@inheritDoc}
 */
abstract class AbstractTypedHasher extends AbstractHasher implements TypedHasherInterface
{

    /**
     * Properties
     */

    /**
     * The algorithm used.
     *
     * Maps to a {@link HasherAlgorithm} value.
     *
     * @type string
     */
    private $algorithm;


    /**
     * Methods
     */

    /**
     * Constructor
     *
     * @param resource $context The incremental hashing context.
     */
    protected function __construct($context, $algorithm)
    {
        parent::__construct($context);

        $this->algorithm = $algorithm;
    }

    /**
     * {@inheritDoc}
     */
    public function getAlgorithm()
    {
        return $this->algorithm;
    }
}
