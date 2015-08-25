<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Message;

/**
 * A value object containing the values issued by a server challenge message.
 */
class ServerChallenge
{

    /**
     * Properties
     */

    /**
     * A 64-bit (8-byte) unsigned "nonce" (number used once) represented as a
     * binary numeric string.
     *
     * NOTE: This is stored and represented as a string, rather than a native
     * numeric value, due to limitations with PHP's number system. The value is
     * an unsigned 64-bit integer, which doesn't fit in the native numeric type
     * even on 64-bit PHP installations.
     *
     * @type string
     */
    private $nonce;

    /**
     * The negotiate flags represented as a 32-bit (4-byte) unsigned integer,
     * with each separate value represented as a binary string of joined
     * {@link NegotiateFlag} constants.
     *
     * @type int
     */
    private $negotiate_flags;

    /**
     * The "TargetName" as reported by the server, which represents a different
     * value depending on the negotiated target type.
     *
     * @type string
     */
    private $target_name;


    /**
     * Methods
     */

    /**
     * Constructor
     *
     * @param string $nonce A 64-bit (8-byte) unsigned "nonce" (number used
     *   once) represented as a binary numeric string.
     * @param int $negotiate_flags The negotiate flags represented as a 32-bit
     *   unsigned integer.
     * @param string $target_name The "TargetName" as reported by the server, as
     *   a decoded string.
     */
    public function __construct($nonce, $negotiate_flags, $target_name)
    {
        $this->nonce = $nonce;
        $this->negotiate_flags = $negotiate_flags;
        $this->target_name = $target_name;
    }

    /**
     * Gets the 64-bit (8-byte) unsigned "nonce".
     *
     * @return string The nonce represented as a binary numeric string.
     */
    public function getNonce()
    {
        return $this->nonce;
    }

    /**
     * Gets the 32-bit (4-byte) negotiate flags.
     *
     * @return int The flags represented as a 32-bit unsigned integer.
     */
    public function getNegotiateFlags()
    {
        return $this->negotiate_flags;
    }

    /**
     * Gets the "TargetName".
     *
     * @return string
     */
    public function getTargetName()
    {
        return $this->target_name;
    }
}
