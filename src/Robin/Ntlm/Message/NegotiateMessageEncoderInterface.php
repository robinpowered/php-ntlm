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
 */
interface NegotiateMessageEncoderInterface
{

    /**
     * Encodes an NTLM "NEGOTIATE_MESSAGE".
     *
     * @param string $nt_domain The domain name of the NT user authenticating.
     * @param string $client_hostname The hostname of the client (the hostname
     *   of the machine calling this code).
     * @return string The encoded message as a binary string.
     */
    public function encode($nt_domain, $client_hostname);
}
