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
     * Constants
     */

    /**
     * The "resource" type of a PHP hash context.
     *
     * @type string
     */
    const HASH_CONTEXT_RESOURCE_TYPE = 'Hash Context';


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
    protected $algorithm;

    /**
     * The incremental hashing context.
     *
     * @link http://php.net/manual/en/hash.resources.php
     * @type resource
     */
    protected $context;


    /**
     * Methods
     */

    /**
     * Constructor
     *
     * @param string $algorithm The {@link HasherAlgorithm} to use.
     */
    public function __construct($algorithm)
    {
        $this->algorithm = $algorithm;

        $context = hash_init($this->algorithm);

        $this->context = $this->validateHashContext($context);
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

    /**
     * Validates a given incremental hashing context.
     *
     * @link http://php.net/manual/en/hash.resources.php
     * @param mixed $context The context to validate.
     * @return resource The incremental hashing context.
     */
    protected function validateHashContext($context)
    {
        if (false === $context
            || !is_resource($context)
            || (is_resource($context) && static::HASH_CONTEXT_RESOURCE_TYPE !== get_resource_type())) {
            throw new UnexpectedValueException(
                sprintf(
                    'Unable to initialize hashing context. Your system might not currently support the "%s" algorithm.',
                    $this->algorithm
                )
            );
        }

        return $context;
    }
}
