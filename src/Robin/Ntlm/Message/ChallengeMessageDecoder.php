<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Message;

use Robin\Ntlm\Message\NegotiateFlag;
use UnexpectedValueException;

/**
 * {@inheritDoc}
 */
class ChallengeMessageDecoder implements ChallengeMessageDecoderInterface
{

    /**
     * Constants
     */

    /**
     * The minimum length of a valid message, in bytes.
     *
     * @type int
     */
    const MINIMUM_MESSAGE_LENGTH = 32;

    /**
     * An 8-byte string denoting the protocol in use.
     *
     * @type string
     */
    const SIGNATURE = "NTLMSSP\0";

    /**
     * A 32-bit unsigned integer indicating the message type.
     *
     * @type int
     */
    const MESSAGE_TYPE = 0x00000002;

    /**
     * The offset in the binary message string of the signature, in bytes.
     *
     * @type int
     */
    const SIGNATURE_OFFSET = 0;

    /**
     * The offset in the binary message string of the message type, in bytes.
     *
     * @type int
     */
    const MESSAGE_TYPE_OFFSET = 8;

    /**
     * The offset in the binary message string of the "TargetName" length, in
     * bytes.
     *
     * @type int
     */
    const TARGET_NAME_LENGTH_OFFSET = 12;

    /**
     * The offset in the binary message string of the "TargetName" offset, in
     * bytes.
     *
     * @type int
     */
    const TARGET_NAME_BUFFER_OFFSET_OFFSET = 16;

    /**
     * The offset in the binary message string of the negotiate flags, in bytes.
     *
     * @type int
     */
    const NEGOTIATE_FLAGS_OFFSET = 20;

    /**
     * The length of the chunk of the binary message string that contains the
     * negotiate flags, in bytes.
     *
     * @type int
     */
    const NEGOTIATE_FLAGS_LENGTH = 4;

    /**
     * The offset in the binary message string of the server challenge "nonce",
     * in bytes.
     *
     * @type int
     */
    const CHALLENGE_NONCE_OFFSET = 24;

    /**
     * The length of the chunk of the binary message string that contains the
     * server challenge "nonce", in bytes.
     *
     * @type int
     */
    const CHALLENGE_NONCE_LENGTH = 8;

    /**
     * The offset in the binary message string of the "target info" length, in
     * bytes.
     *
     * @type int
     */
    const TARGET_INFO_LENGTH_OFFSET = 40;

    /**
     * The offset in the binary message string of the "target info" offset, in
     * bytes.
     *
     * @type int
     */
    const TARGET_INFO_BUFFER_OFFSET_OFFSET = 44;


    /**
     * Methods
     */

    /**
     * {@inheritDoc}
     */
    public function decode($challenge_message)
    {
        if (!is_string($challenge_message) || static::MINIMUM_MESSAGE_LENGTH >= strlen($challenge_message)) {
            throw new UnexpectedValueException(
                sprintf(
                    'Provided challenge message isn\'t a %d-byte (or longer) string',
                    static::MINIMUM_MESSAGE_LENGTH
                )
            );
        }

        // Grab the signature from the expected byte range
        $signature = substr($challenge_message, static::SIGNATURE_OFFSET, strlen(static::SIGNATURE));

        if (static::SIGNATURE !== $signature) {
            throw new UnexpectedValueException('Invalid message signature');
        }

        $message_type = unpack('V', substr($challenge_message, static::MESSAGE_TYPE_OFFSET, 4))[1];

        if (static::MESSAGE_TYPE !== $message_type) {
            throw new UnexpectedValueException('Invalid message type');
        }

        $target_name_length = unpack('v', substr($challenge_message, static::TARGET_NAME_LENGTH_OFFSET, 2))[1];
        $target_name_offset = unpack('V', substr($challenge_message, static::TARGET_NAME_BUFFER_OFFSET_OFFSET, 4))[1];

        $negotiate_flags_raw = substr(
            $challenge_message,
            static::NEGOTIATE_FLAGS_OFFSET,
            static::NEGOTIATE_FLAGS_LENGTH
        );
        $negotiate_flags = unpack('V', $negotiate_flags_raw)[1];

        $challenge_nonce = substr($challenge_message, static::CHALLENGE_NONCE_OFFSET, static::CHALLENGE_NONCE_LENGTH);

        $target_info_length = unpack('v', substr($challenge_message, static::TARGET_INFO_LENGTH_OFFSET, 2))[1];
        $target_info_offset = unpack('V', substr($challenge_message, static::TARGET_INFO_BUFFER_OFFSET_OFFSET, 4))[1];

        // Grab our payload data
        $target_name = null;
        $target_info = null;

        // Only actually decode the "TargetName" if we're told to
        if ((NegotiateFlag::REQUEST_TARGET & $negotiate_flags)
            === NegotiateFlag::REQUEST_TARGET) {
            $target_name = unpack('a*', substr($challenge_message, $target_name_offset, $target_name_length))[1];
        }

        // Only actually decode the target info if we're told to
        if ((NegotiateFlag::NEGOTIATE_TARGET_INFO & $negotiate_flags)
            === NegotiateFlag::NEGOTIATE_TARGET_INFO) {
            $target_info = unpack('a*', substr($challenge_message, $target_info_offset, $target_info_length))[1];
        }

        return new ServerChallenge(
            $challenge_nonce,
            $negotiate_flags,
            $target_name,
            $target_info
        );
    }
}
