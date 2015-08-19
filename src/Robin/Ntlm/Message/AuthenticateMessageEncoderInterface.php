<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Message;

use Robin\Ntlm\Credential\CredentialInterface;

/**
 * Encodes an NTLM "AUTHENTICATE_MESSAGE" to be used in the client-server
 * challenge/response flow.
 *
 * @link https://msdn.microsoft.com/en-us/library/cc236643.aspx
 */
interface AuthenticateMessageEncoderInterface
{

    /**
     * Encodes an NTLM "AUTHENTICATE_MESSAGE".
     *
     * @param string $username The user's "username".
     * @param string $nt_domain The domain name of the NT user authenticating.
     * @param string $client_hostname The hostname of the client (the hostname
     *   of the machine calling this code).
     * @param CredentialInterface $credential The user's authentication
     *   credential, whether it be a plain-text password or a previously hashed
     *   representation.
     * @param ServerChallenge $server_challenge The value of a decoded NTLM
     *   server's "CHALLENGE_MESSAGE".
     * @return string The encoded message as a binary string.
     */
    public function encode(
        $username,
        $nt_domain,
        $client_hostname,
        CredentialInterface $credential,
        ServerChallenge $server_challenge
    );
}
