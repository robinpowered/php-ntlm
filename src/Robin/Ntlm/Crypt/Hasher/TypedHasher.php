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
 * A cryptographic hasher implemented using PHP's built-in hashing mechanisms as
 * part of the "hash" extension (`ext-hash`).
 *
 * @link http://php.net/manual/en/ref.hash.php
 */
class TypedHasher implements TypedHasherInterface
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
     * The incremental hashing context.
     *
     * @link http://php.net/manual/en/hash.resources.php
     * @type resource
     */
    private $context;


    /**
     * Methods
     */

    /**
     * Constructor
     */
    public function __construct($algorithm)
    {
        $this->algorithm = $algorithm;

        $context = hash_init($this->algorithm);

        if (false === $context) {
            throw new UnexpectedValueException(
                sprintf(
                    'Unable to initialize hashing context. Your system might not currently support the "%s" algorithm.',
                    $this->algorithm
                )
            );
        }

        $this->context = $context;
    }

    /**
     * {@inheritDoc}
     */
    public function update($data)
    {
        hash_update($this->context, $data);

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function digest()
    {
        return hash_final($this->context, true);
    }

    /**
     * {@inheritDoc}
     */
    public function getAlgorithm()
    {
        return $this->algorithm;
    }
}
