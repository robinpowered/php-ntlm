<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Message;

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
     * Methods
     */

    /**
     * {@inheritDoc}
     */
    public function decode($challenge_message)
    {
        if (!is_string($challenge_message) || static::MINIMUM_MESSAGE_LENGTH <= strlen($challenge_message)) {
            throw new UnexpectedValueException(
                sprintf(
                    'Provided challenge message isn\'t a %d-byte (or longer) string',
                    static::MINIMUM_MESSAGE_LENGTH
                )
            );
        }

        // Split the message into its bytes
        $message_byte_array = str_split($challenge_message, 1);

        // Grab the signature from the expected byte range
        $signature = array_reduce(
            array_slice($message_byte_array, static::SIGNATURE_OFFSET, strlen(static::SIGNATURE)),
            function ($string, $ordinal) {
                return ($string . chr($ordinal));
            }
        );

        if (static::SIGNATURE !== $signature) {
            throw new UnexpectedValueException('Invalid message signature');
        }

        $message_type = unpack('V', substr($challenge_message, static::MESSAGE_TYPE_OFFSET, 4));

        if (static::MESSAGE_TYPE !== $message_type) {
            throw new UnexpectedValueException('Invalid message type');
        }

        // Grab our relevant data
        $negotiate_flags = substr($challenge_message, static::NEGOTIATE_FLAGS_OFFSET, static::NEGOTIATE_FLAGS_LENGTH);
        $challenge_nonce = substr($challenge_message, static::CHALLENGE_NONCE_OFFSET, static::CHALLENGE_NONCE_LENGTH);

        return new ServerChallenge(
            $challenge_nonce,
            unpack('V', $negotiate_flags)
        );
    }
}
