<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Hasher;

use Robin\Ntlm\Credential\HashCredentialInterface;
use Robin\Ntlm\Credential\Password;

/**
 * Hashes a {@link Password} credential and user-identifying meta-data into a
 * {@link HashCredentialInterface}.
 */
interface IdentityMetaHasherInterface
{

    /**
     * Hash a given {@link Password} into a {@link HashCredentialInterface}.
     *
     * @param Password $password The password to hash.
     * @param string $username The user's "username".
     * @param string $domain_name The user's server domain-name.
     * @return HashCredentialInterface The resulting hash.
     */
    public function hash(Password $password, $username, $domain_name);
}
