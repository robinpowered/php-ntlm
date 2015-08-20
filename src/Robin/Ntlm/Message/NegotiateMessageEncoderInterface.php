<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Message;

/**
 * Encodes an NTLM "NEGOTIATE_MESSAGE" to be used in the client-server
 * challenge/response flow.
 *
 * @link https://msdn.microsoft.com/en-us/library/cc236641.aspx
 */
interface NegotiateMessageEncoderInterface
{

    /**
     * Encodes an NTLM "NEGOTIATE_MESSAGE".
     *
     * @param string $nt_domain The domain name of the NT user authenticating.
     * @param string $client_hostname The hostname of the client (the hostname
     *   of the machine calling this code).
     * @param int|null $negotiate_flags A 32-bit unsigned integer representing
     *   the flags to be negotiated with the authentication server. Optionally
     *   specified, so implementations should provide accessible default flags.
     * @return string The encoded message as a binary string.
     */
    public function encode($nt_domain, $client_hostname, $negotiate_flags = null);
}
