<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Credential;

/**
 * Represents a hashed (one-way encrypted) credential.
 *
 * This representation is safe for storage, as the plain-text password can't be
 * determined from this representation.
 */
final class Hash implements HashCredentialInterface
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
     * The type of hash represented.
     *
     * Maps to a {@link HashType} value.
     *
     * @type int
     */
    private $type = HashType::UNKNOWN;


    /**
     * Methods
     */

    /**
     * Constructs a hash from a raw binary string.
     *
     * @param string $binary_hash The raw binary string representation.
     * @param int $type The {@link HashType type} of hash being represented.
     * @return self
     */
    public static function fromBinaryString($binary_hash, $type)
    {
        return new self($binary_hash, $type);
    }

    /**
     * Constructs a hash from a hexadecimally encoded binary string.
     *
     * @param string $hex_binary_hash The hex binary string representation.
     * @param int $type The {@link HashType type} of hash being represented.
     * @return self
     */
    public static function fromHexBinaryString($hex_binary_hash, $type)
    {
        return static::fromBinaryString(
            hex2bin($hex_binary_hash),
            $type
        );
    }

    /**
     * Constructor
     *
     * Private so that the named constructors must be used to deter confusion
     * and improper encoding.
     *
     * @param string $hash The raw binary hash string.
     * @param int $type The {@link HashType type} of hash being represented.
     */
    private function __construct($hash, $type)
    {
        $this->value = $hash;

        // If the type was passed as null, default to the "unknown" type
        $this->type = (null !== $type) ? $type : HashType::UNKNOWN;
    }

    /**
     * {@inheritDoc}
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * {@inheritDoc}
     */
    public function isPlaintext()
    {
        return false;
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
    public function getHexEncodedValue()
    {
        return bin2hex($this->getValue());
    }

    /**
     * {@inheritDoc}
     */
    public function __toString()
    {
        return $this->getHexEncodedValue();
    }
}
