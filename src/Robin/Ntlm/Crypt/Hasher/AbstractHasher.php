<?php
/**
 * Robin NTLM
 *
 * @copyright 2019 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

declare(strict_types=1);

namespace Robin\Ntlm\Crypt\Hasher;

use HashContext;

/**
 * A cryptographic hasher implemented using PHP's built-in hashing mechanisms as
 * part of the "hash" extension (`ext-hash`).
 *
 * @link http://php.net/manual/en/ref.hash.php
 */
abstract class AbstractHasher implements HasherInterface
{
    /**
     * The incremental hashing context.
     *
     * @type HashContext
     */
    private $context;

    /**
     * Constructor
     *
     * @param HashContext $context The incremental hashing context.
     */
    protected function __construct(HashContext $context)
    {
        $this->context = $context;
    }

    /**
     * {@inheritDoc}
     */
    public function update(string $data): HasherInterface
    {
        hash_update($this->context, $data);

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function digest(): string
    {
        // Copy the context so we can keep using the hasher
        $context_copy = hash_copy($this->context);

        // Calculate the digest
        $digest = hash_final($this->context, true);

        // Set our context to the copied one, since the old one is now finalized
        $this->context = $context_copy;

        return $digest;
    }
}
