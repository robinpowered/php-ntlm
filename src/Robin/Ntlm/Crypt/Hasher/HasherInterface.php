<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Hasher;

/**
 * An engine used to cryptographically hash data into a message digest.
 *
 * Not to be confused with the
 * {@link \Robin\Ntlm\Hasher\HasherInterface credential hasher}
 */
interface HasherInterface
{

    /**
     * Adds data to the message to be digested.
     *
     * @param string $data The data to add.
     * @return $this
     */
    public function update($data);

    /**
     * Calculates the digest of the message.
     *
     * @return string The message digest as a binary string.
     */
    public function digest();
}
