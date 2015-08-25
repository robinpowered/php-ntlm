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
     * The "TargetInfo" as a raw binary string. This raw binary string contains
     * a specialized structure known as "AV_PAIRs", and can be further decoded
     * into its documented parts if necessary.
     *
     * @type string
     */
    private $target_info;


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
     * @param string $target_info The "TargetInfo" as a raw binary string.
     */
    public function __construct($nonce, $negotiate_flags, $target_name, $target_info)
    {
        $this->nonce = $nonce;
        $this->negotiate_flags = $negotiate_flags;
        $this->target_name = $target_name;
        $this->target_info = $target_info;
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
     * @return string The target name represented as a decoded string.
     */
    public function getTargetName()
    {
        return $this->target_name;
    }

    /**
     * Gets the "TargetInfo".
     *
     * @return string The target info represented as a raw binary string.
     */
    public function getTargetInfo()
    {
        return $this->target_info;
    }
}
