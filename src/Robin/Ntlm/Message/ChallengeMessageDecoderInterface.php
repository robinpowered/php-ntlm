<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Message;

/**
 * Decodes an NTLM "CHALLENGE_MESSAGE" to be used in the client-server
 * challenge/response flow.
 *
 * @link https://msdn.microsoft.com/en-us/library/cc236642.aspx
 */
interface ChallengeMessageDecoderInterface
{

    /**
     * Decodes an NTLM "CHALLENGE_MESSAGE".
     *
     * @param string $challenge_message The NTLM "CHALLENGE_MESSAGE" data,
     *   represented as a binary string.
     * @return ServerChallenge The decoded server challenge.
     */
    public function decode($challenge_message);
}
