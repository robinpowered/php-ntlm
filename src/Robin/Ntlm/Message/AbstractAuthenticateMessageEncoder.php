<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Message;

use Robin\Ntlm\Encoding\EncodingConverterInterface;

/**
 * {@inheritDoc}
 */
abstract class AbstractAuthenticateMessageEncoder implements AuthenticateMessageEncoderInterface
{

    /**
     * Constants
     */

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
    const MESSAGE_TYPE = 0x00000003;

    /**
     * The character encoding used for "OEM" encoded values.
     *
     * @type string
     */
    const OEM_ENCODING = 'ASCII';

    /**
     * The character encoding used for Unicode encoded values.
     *
     * @type string
     */
    const UNICODE_ENCODING = 'UTF-16LE';

    /**
     * The character used for null padding.
     *
     * @type string
     */
    const NULL_PAD_CHARACTER = "\0";

    /**
     * The length of the client challenge to generate, if necessary, in bytes.
     *
     * @type int
     */
    const CLIENT_CHALLENGE_LENGTH = 8;

    /**
     * The length of the LM response.
     *
     * @type int
     */
    const LM_RESPONSE_LENGTH = 24;


    /**
     * Properties
     */

    /**
     * Used to convert encodings of strings before adding them to the message.
     *
     * @type EncodingConverterInterface
     */
    protected $encoding_converter;


    /**
     * Methods
     */

    /**
     * Constructor
     *
     * @param EncodingConverterInterface $encoding_converter Used to convert
     *   encodings of strings before adding them to the message.
     */
    protected function __construct(EncodingConverterInterface $encoding_converter)
    {
        $this->encoding_converter = $encoding_converter;
    }

    /**
     * Encodes the binary "AUTHENTICATE_MESSAGE" string from its provided parts.
     *
     * @param int $negotiate_flags The negotiation flags encoded in the message.
     * @param string $lm_challenge_response The calcualted LM response.
     * @param string $nt_challenge_response The calcualted NT response.
     * @param string $target_name The "TargetName" (domain/server name) of the
     *   NT user authenticating.
     * @param string $username The user's "username".
     * @param string $client_hostname The hostname of the client (the hostname
     *   of the machine calling this code).
     * @param string $session_key The session key used in NTLM key exchange.
     * @return string The encoded message as a binary string.
     */
    public function encodeBinaryMessageString(
        $negotiate_flags,
        $lm_challenge_response,
        $nt_challenge_response,
        $target_name,
        $username,
        $client_hostname,
        $session_key
    ) {
        // If expecting unicode
        if ((NegotiateFlag::NEGOTIATE_UNICODE & $negotiate_flags) === NegotiateFlag::NEGOTIATE_UNICODE) {
            $expected_encoding = static::UNICODE_ENCODING;
        } else {
            $expected_encoding = static::OEM_ENCODING;
        }

        // Convert our provided values to proper encoding
        $username = $this->encoding_converter->convert($username, $expected_encoding);
        $target_name = $this->encoding_converter->convert(strtoupper($target_name), $expected_encoding);
        $client_hostname = $this->encoding_converter->convert(strtoupper($client_hostname), $expected_encoding);
        $session_key = $this->encoding_converter->convert(strtoupper($session_key), $expected_encoding);

        $payload_offset = static::calculatePayloadOffset($negotiate_flags);
        $message_position = $payload_offset;

        // Prepare a binary string to be returned
        $binary_string = '';

        $binary_string .= static::SIGNATURE; // 8-byte signature
        $binary_string .= pack('V', static::MESSAGE_TYPE); // 32-bit unsigned little-endian

        $lm_response_length = strlen($lm_challenge_response);

        // LM challenge response fields: length; length; offset of the value from the beginning of the message
        $binary_string .= pack('v', $lm_response_length); // 16-bit unsigned little-endian
        $binary_string .= pack('v', $lm_response_length); // 16-bit unsigned little-endian
        $binary_string .= pack('V', $message_position); // 32-bit unsigned little-endian, 1st value in the payload
        $message_position += $lm_response_length;

        $nt_response_length = strlen($nt_challenge_response);

        // NT challenge response fields: length; length; offset of the value from the beginning of the message
        $binary_string .= pack('v', $nt_response_length); // 16-bit unsigned little-endian
        $binary_string .= pack('v', $nt_response_length); // 16-bit unsigned little-endian
        $binary_string .= pack('V', $message_position); // 32-bit unsigned little-endian, 1st value in the payload
        $message_position += $nt_response_length;

        $target_name_length = strlen($target_name);

        // Domain name fields: length; length; offset of the value from the beginning of the message
        $binary_string .= pack('v', $target_name_length); // 16-bit unsigned little-endian
        $binary_string .= pack('v', $target_name_length); // 16-bit unsigned little-endian
        $binary_string .= pack('V', $message_position); // 32-bit unsigned little-endian, 1st value in the payload
        $message_position += $target_name_length;

        $username_length = strlen($username);

        // Domain name fields: length; length; offset of the value from the beginning of the message
        $binary_string .= pack('v', $username_length); // 16-bit unsigned little-endian
        $binary_string .= pack('v', $username_length); // 16-bit unsigned little-endian
        $binary_string .= pack('V', $message_position); // 32-bit unsigned little-endian, 1st value in the payload
        $message_position += $username_length;

        $hostname_length = strlen($client_hostname);

        // Domain name fields: length; length; offset of the value from the beginning of the message
        $binary_string .= pack('v', $hostname_length); // 16-bit unsigned little-endian
        $binary_string .= pack('v', $hostname_length); // 16-bit unsigned little-endian
        $binary_string .= pack('V', $message_position); // 32-bit unsigned little-endian, 1st value in the payload
        $message_position += $hostname_length;

        $session_key_length = strlen($session_key);

        // Domain name fields: length; length; offset of the value from the beginning of the message
        $binary_string .= pack('v', $session_key_length); // 16-bit unsigned little-endian
        $binary_string .= pack('v', $session_key_length); // 16-bit unsigned little-endian
        $binary_string .= pack('V', $message_position); // 32-bit unsigned little-endian, 1st value in the payload
        $message_position += $session_key_length;

        $binary_string .= pack('V', $negotiate_flags);

        // Add our payload data
        $binary_string .= $lm_challenge_response;
        $binary_string .= $nt_challenge_response;
        $binary_string .= $target_name;
        $binary_string .= $username;
        $binary_string .= $client_hostname;
        $binary_string .= $session_key;

        return $binary_string;
    }

    /**
     * Calculates the offset of the "Payload" in the encoded message from the
     * most-significant bit.
     *
     * @param int $negotiate_flags The negotiation flags encoded in the message.
     * @return int The offset, in bytes.
     */
    public static function calculatePayloadOffset($negotiate_flags)
    {
        $offset = 0;

        $offset += strlen(static::SIGNATURE); // 8-byte signature
        $offset += 4; // Message-type indicator

        $offset += 8; // 64-bit LM challenge response field designator
        $offset += 8; // 64-bit NT challenge response field designator

        $offset += 8; // 64-bit domain name field designator
        $offset += 8; // 64-bit username field designator
        $offset += 8; // 64-bit client hostname field designator

        $offset += 8; // 64-bit session key field designator

        $offset += 4; // 32-bit Negotation flags

        return $offset;
    }
}
