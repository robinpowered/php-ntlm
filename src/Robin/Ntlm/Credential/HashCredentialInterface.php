<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Credential;

/**
 * Represents an NTLM hash credential to be used in the process of generating
 * the requests/responses in the challenge-response process and also suitable
 * for long-term storage.
 */
interface HashCredentialInterface extends CredentialInterface
{

    /**
     * Gets the type of hash.
     *
     * @return int Maps to a {@link HashType} value.
     */
    public function getType();

    /**
     * Gets the value of the credential encoded as a hexadecimal string.
     *
     * Useful for ASCII storage of the binary value.
     *
     * @return string
     */
    public function getHexEncodedValue();
}
