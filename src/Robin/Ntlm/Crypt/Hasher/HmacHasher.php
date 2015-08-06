<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Hasher;

/**
 * A cryptographic hasher that uses a cryptographic secret key as part of its
 * digest calculation to create an HMAC (hash-based message authentication code)
 * and implemented using PHP's built-in hashing mechanisms as part of the "hash"
 * extension (`ext-hash`).
 *
 * @link https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
 * @link http://php.net/manual/en/ref.hash.php
 */
class HmacHasher extends AbstractTypedHasher
{

    /**
     * Constructor
     *
     * @param string $algorithm The {@link HasherAlgorithm} to use.
     * @param string $key The cryptographic key used in the hasher's digest
     *   calculation algorithm.
     */
    public function __construct($algorithm, $key)
    {
        $context = hash_init($algorithm, HASH_HMAC, $key);

        parent::__construct($context, $algorithm);
    }
}
