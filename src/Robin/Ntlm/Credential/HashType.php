<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Credential;

/**
 * Constant definitions of types of NTLM-compatible hashes.
 */
final class HashType
{

    /**
     * An unknown hash type.
     *
     * Used when the type of hash isn't known.
     *
     * @type int
     */
    const UNKNOWN = -1;

    /**
     * The "LM" hash type.
     *
     * @type int
     */
    const LM = 1;

    /**
     * The "NT" hash type; version 1.
     *
     * @type int
     */
    const NT_V1 = 16;

    /**
     * The "NT" hash type; version 2.
     *
     * @type int
     */
    const NT_V2 = 32;
}
