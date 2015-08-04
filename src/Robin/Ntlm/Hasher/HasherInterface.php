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
 * Hashes a {@link Password} credential into a {@link HashCredentialInterface}.
 */
interface HasherInterface
{

    /**
     * Hash a given {@link Password} into a {@link HashCredentialInterface}.
     *
     * @param Password $password The password to hash.
     * @return HashCredentialInterface The resulting hash.
     */
    public function hash(Password $password);
}
