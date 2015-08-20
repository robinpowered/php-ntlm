<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Credential;

/**
 * Represents a plain-text password credential.
 */
final class Password implements CredentialInterface
{

    /**
     * Properties
     */

    /**
     * The internal string value.
     *
     * @type string
     */
    private $value;


    /**
     * Methods
     */

    /**
     * Constructor
     *
     * @param string $plaintext_password The plain-text password string.
     */
    public function __construct($plaintext_password)
    {
        $this->value = $plaintext_password;
    }

    /**
     * {@inheritDoc}
     */
    public function isPlaintext()
    {
        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * {@inheritDoc}
     */
    public function __toString()
    {
        return $this->getValue();
    }
}
