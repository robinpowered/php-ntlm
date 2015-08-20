<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Message;

use Robin\Ntlm\Credential\CredentialInterface;
use Robin\Ntlm\Credential\HashCredentialInterface;
use Robin\Ntlm\Credential\HashType;
use Robin\Ntlm\Crypt\CipherMode;
use Robin\Ntlm\Crypt\Des\DesEncrypterInterface;
use Robin\Ntlm\Crypt\Random\RandomByteGeneratorInterface;
use Robin\Ntlm\Encoding\EncodingConverterInterface;
use Robin\Ntlm\Hasher\HasherInterface;
use UnexpectedValueException;

/**
 * {@inheritDoc}
 *
 * Uses the NTLMv1 protocol for encoding the "AUTHENTICATE_MESSAGE".
 */
class NtlmV1AuthenticateMessageEncoder implements AuthenticateMessageEncoderInterface
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
     * The length of the full DESL (DES "Long") key source before splitting into
     * blocks, in bytes.
     *
     * @link https://msdn.microsoft.com/en-us/library/cc236717.aspx
     * @type int
     */
    const DESL_FULL_KEY_LENGTH = 21;

    /**
     * The length of each DESL (DES "Long") key block, in bytes.
     *
     * @link https://msdn.microsoft.com/en-us/library/cc236717.aspx
     * @type int
     */
    const DESL_KEY_BLOCK_SEGMENT_LENGTH = 7;


    /**
     * Properties
     */

    /**
     * Used to convert encodings of strings before adding them to the message.
     *
     * @type EncodingConverterInterface
     */
    private $encoding_converter;

    /**
     * Used to create the "LM hash" in the message.
     *
     * @type HasherInterface
     */
    private $lm_hasher;

    /**
     * Used to create the "NT hash" in the message.
     *
     * @type HasherInterface
     */
    private $nt_hasher;

    /**
     * Used to create encryption initialization vectors and to generate random
     * client challenges for extended security support.
     *
     * @type RandomByteGeneratorInterface
     */
    private $random_byte_generator;

    /**
     * Used to compute challenge responses for the different message hashes.
     *
     * @type DesEncrypterInterface
     */
    private $des_encrypter;


    /**
     * Methods
     */

    /**
     * Constructor
     *
     * @param EncodingConverterInterface $encoding_converter Used to convert
     *   encodings of strings before adding them to the message.
     * @param HasherInterface $lm_hasher Used to create the "LM hash".
     * @param HasherInterface $nt_hasher Used to create the "NT hash".
     * @param RandomByteGeneratorInterface $random_byte_generator Used to create
     *   encryption initialization vectors and to generate random client
     *   challenges for extended security support.
     * @param DesEncrypterInterface $des_encrypter Used to compute challenge
     *   responses for the different message hashes.
     */
    public function __construct(
        EncodingConverterInterface $encoding_converter,
        HasherInterface $lm_hasher,
        HasherInterface $nt_hasher,
        RandomByteGeneratorInterface $random_byte_generator,
        DesEncrypterInterface $des_encrypter
    ) {
        $this->encoding_converter = $encoding_converter;
        $this->lm_hasher = $lm_hasher;
        $this->nt_hasher = $nt_hasher;
        $this->random_byte_generator = $random_byte_generator;
        $this->des_encrypter = $des_encrypter;
    }

    /**
     * {@inheritDoc}
     */
    public function encode(
        $username,
        $nt_domain,
        $client_hostname,
        CredentialInterface $credential,
        ServerChallenge $server_challenge
    ) {
        $negotiate_flags = $server_challenge->getNegotiateFlags();
        $server_challenge_nonce = $server_challenge->getNonce();

        // If expecting unicode
        if ((NegotiateFlag::NEGOTIATE_UNICODE & $negotiate_flags) === NegotiateFlag::NEGOTIATE_UNICODE) {
            $expected_encoding = static::UNICODE_ENCODING;
        } else {
            $expected_encoding = static::OEM_ENCODING;
        }

        // TODO: Generate an encrypted random session key
        $session_key = '';

        // Convert our provided values to proper encoding
        $username = $this->encoding_converter->convert($username, $expected_encoding);
        $nt_domain = $this->encoding_converter->convert(strtoupper($nt_domain), $expected_encoding);
        $client_hostname = $this->encoding_converter->convert(strtoupper($client_hostname), $expected_encoding);
        $session_key = $this->encoding_converter->convert(strtoupper($session_key), $expected_encoding);

        // Default hash and challenge responsevalues
        $lm_hash = null;
        $nt_hash = null;
        $lm_challenge_response = null;
        $nt_challenge_response = null;

        if ($credential->isPlaintext()) {
            $lm_hash = $this->lm_hasher->hash($credential);
            $nt_hash = $this->nt_hasher->hash($credential);
        } elseif ($credential instanceof HashCredentialInterface) {
            switch ($credential->getType()) {
                case HashType::LM:
                    $lm_hash = $credential;
                    break;
                case HashType::NT_V1:
                    $nt_hash = $credential;
                    break;
                default:
                    throw new UnexpectedValueException('Unsupported hash credential type');
            }
        }

        if (null !== $lm_hash) {
            $lm_challenge_response = $this->calculateChallengeResponseData($lm_hash, $server_challenge_nonce);
        }

        if (null !== $nt_hash) {
            $nt_challenge_response = $this->calculateChallengeResponseData($nt_hash, $server_challenge_nonce);
        }

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

        $domain_name_length = strlen($nt_domain);

        // Domain name fields: length; length; offset of the value from the beginning of the message
        $binary_string .= pack('v', $domain_name_length); // 16-bit unsigned little-endian
        $binary_string .= pack('v', $domain_name_length); // 16-bit unsigned little-endian
        $binary_string .= pack('V', $message_position); // 32-bit unsigned little-endian, 1st value in the payload
        $message_position += $domain_name_length;

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
        $binary_string .= $nt_domain;
        $binary_string .= $username;
        $binary_string .= $client_hostname;
        $binary_string .= $session_key;

        return $binary_string;
    }

    /**
     * Calculates a response to a server challenge for a given credential hash.
     *
     * @param HashCredentialInterface $hash_credential The authentication
     *   credential hash to compute the response for.
     * @param string $nonce The 64-bit (8-byte) unsigned server-sent "nonce"
     *   (number used once) represented as a binary numeric string.
     * @return string The calculated challenge response data as a binary string.
     */
    public function calculateChallengeResponseData(HashCredentialInterface $hash_credential, $nonce)
    {
        // Nul pad the credential hash to the full key size
        $padded_hash = pack(
            'a'. static::DESL_FULL_KEY_LENGTH,
            $hash_credential->getValue()
        );

        $key_blocks = str_split($padded_hash, static::DESL_KEY_BLOCK_SEGMENT_LENGTH);

        $binary_data = array_reduce(
            $key_blocks,
            function ($result, $key_block) use ($nonce) {
                // Generate an initialization vector equal to the length of the nonce
                $initialization_vector = $this->random_byte_generator->generate(strlen($nonce));

                return $result . $this->des_encrypter->encrypt(
                    $key_block,
                    $nonce,
                    CipherMode::ECB,
                    $initialization_vector
                );
            },
            ''
        );

        return $binary_data;
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
