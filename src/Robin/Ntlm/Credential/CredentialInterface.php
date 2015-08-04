<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Credential;

/**
 * Represents an NTLM credential to be used in the process of hashing and/or
 * generating the requests/responses in the challenge-response process.
 */
interface CredentialInterface
{

    /**
     * Checks if the credential is a "plain-text" representation or not.
     *
     * @return bool True if the credential is "plain-text" or false if the
     *   credential is a hash or calculated value.
     */
    public function isPlaintext();

    /**
     * Gets the value of the credential.
     *
     * @return string
     */
    public function getValue();

    /**
     * Gets a string representation of the credential.
     *
     * This allows to support implicit type conversion to a string type.
     *
     * @return string
     */
    public function __toString();
}
