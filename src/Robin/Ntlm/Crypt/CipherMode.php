<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt;

/**
 * Constant definitions of modes of operation for block ciphers.
 */
final class CipherMode
{

    /**
     * The "CBC" block cipher mode of operation.
     *
     * @type int
     */
    const CBC = 1;

    /**
     * The "CFB" block cipher mode of operation.
     *
     * @type int
     */
    const CFB = 2;

    /**
     * The "ECB" block cipher mode of operation.
     *
     * @type int
     */
    const ECB = 4;

    /**
     * The "OFB" block cipher mode of operation.
     *
     * @type int
     */
    const OFB = 8;
}
