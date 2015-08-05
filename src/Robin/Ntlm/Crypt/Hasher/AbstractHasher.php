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
 * A base for a cryptographic hasher implemented using PHP's built-in hashing
 * mechanisms as part of the "hash" extension (`ext-hash`).
 *
 * @link http://php.net/manual/en/ref.hash.php
 */
abstract class AbstractHasher implements HasherInterface
{

    /**
     * Properties
     */

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
    public function __construct()
    {
        $algorithm = $this->getAlgorithmIdentifier();

        $context = hash_init($algorithm);

        if (false === $context) {
            throw new UnexpectedValueException(
                sprintf(
                    'Unable to initialize hashing context. Your system might not currently support the %s algorithm',
                    $algorithm
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
     * Get the string identifier of the algorithm used by PHP's hash extension.
     *
     * @link http://php.net/manual/en/function.hash-algos.php
     * @return string
     */
    abstract protected function getAlgorithmIdentifier();
}
