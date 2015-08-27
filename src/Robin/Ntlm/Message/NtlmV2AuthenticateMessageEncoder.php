<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Message;

use DateTime;
use InvalidArgumentException;
use Robin\Ntlm\Credential\CredentialInterface;
use Robin\Ntlm\Credential\HashCredentialInterface;
use Robin\Ntlm\Credential\HashType;
use Robin\Ntlm\Crypt\Hasher\HasherAlgorithm;
use Robin\Ntlm\Crypt\Hasher\KeyedHasherFactoryInterface;
use Robin\Ntlm\Crypt\Random\RandomByteGeneratorInterface;
use Robin\Ntlm\Encoding\EncodingConverterInterface;
use Robin\Ntlm\Hasher\IdentityMetaHasherInterface;

/**
 * {@inheritDoc}
 *
 * Uses the NTLMv2 protocol for encoding the "AUTHENTICATE_MESSAGE".
 *
 * @link https://msdn.microsoft.com/en-us/library/cc236700.aspx
 */
class NtlmV2AuthenticateMessageEncoder extends AbstractAuthenticateMessageEncoder
{

    /**
     * Constants
     */

    /**
     * The expected {@link HasherAlgorithm} for the cryptographic hasher used
     * for keyed hashing.
     *
     * @type string
     */
    const KEYED_HASHER_ALGORITHM = HasherAlgorithm::MD5;

    /**
     * The length of the client challenge string to generate.
     *
     * @type int
     */
    const CLIENT_CHALLENGE_LENGTH = 8;

    /**
     * The response version indicator as part of the "temp" blob used in the NT
     * response and base key calculation/generation.
     *
     * @type int
     */
    const BLOB_RESPONSE_VERSION = 1;

    /**
     * The highest response version understood by the client indicator as part
     * of the "temp" blob used in the NT response and base key
     * calculation/generation.
     *
     * @type int
     */
    const BLOB_HIGHEST_RESPONSE_VERSION = 1;


    /**
     * Properties
     */

    /**
     * Used to create the "NT hash" in the message.
     *
     * @type IdentityMetaHasherInterface
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
     * The factory used to build a cryptographic hashing engine for generating
     * different keyed hashes for various parts of the resulting message.
     *
     * @type KeyedHasherFactoryInterface
     */
    private $crypt_hasher_factory;


    /**
     * Methods
     */

    /**
     * Constructor
     *
     * @param EncodingConverterInterface $encoding_converter Used to convert
     *   encodings of strings before adding them to the message.
     * @param IdentityMetaHasherInterface $nt_hasher Used to create the
     *   "NT hash" from a plain-text credential.
     * @param RandomByteGeneratorInterface $random_byte_generator Used to create
     *   encryption initialization vectors and to generate random client
     *   challenges for extended security support.
     * @param KeyedHasherFactoryInterface $crypt_hasher_factory Used to build a
     *   cryptographic hashing engine for generating different keyed hashes for
     *   various parts of the resulting message.
     */
    public function __construct(
        EncodingConverterInterface $encoding_converter,
        IdentityMetaHasherInterface $nt_hasher,
        RandomByteGeneratorInterface $random_byte_generator,
        KeyedHasherFactoryInterface $crypt_hasher_factory
    ) {
        parent::__construct($encoding_converter);

        $this->nt_hasher = $nt_hasher;
        $this->random_byte_generator = $random_byte_generator;
        $this->crypt_hasher_factory = $crypt_hasher_factory;
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
        $target_info = $server_challenge->getTargetInfo();
        $target_name = $server_challenge->getTargetName() ?: $nt_domain;

        // Generate a client challenge
        $client_challenge = $this->random_byte_generator->generate(static::CLIENT_CHALLENGE_LENGTH);

        // Encode the "blob"
        $binary_blob = $this->encodeBlob(new DateTime(), $client_challenge, $target_info);

        if ($credential->isPlaintext()) {
            $nt_hash = $this->nt_hasher->hash($credential, $username, $target_name);
        } elseif ($credential instanceof HashCredentialInterface && HashType::NT_V2 === $credential->getType()) {
            $nt_hash = $credential;
        } else {
            throw new InvalidArgumentException('Unsupported hash credential type');
        }

        $lm_challenge_response = $this->calculateLmResponse(
            $nt_hash,
            $client_challenge,
            $server_challenge_nonce
        );

        $nt_proof_string = $this->calculateNtProofString($nt_hash, $server_challenge_nonce, $binary_blob);

        $nt_challenge_response = ($nt_proof_string . $binary_blob);

        // TODO: Generate an encrypted random session key
        $session_key = '';

        return $this->encodeBinaryMessageString(
            $negotiate_flags,
            $lm_challenge_response,
            $nt_challenge_response,
            $target_name,
            $username,
            $client_hostname,
            $session_key
        );
    }

    /**
     * Calculates the LM response.
     *
     * @param HashCredentialInterface $hash_credential The user's authentication
     *   LM hash credential.
     * @param string $client_challenge A randomly generated 64-bit (8-byte)
     *   unsigned client-generated binary string.
     * @param string $server_challenge_nonce The 64-bit (8-byte) unsigned
     *   server-sent "nonce" (number used once) represented as a binary string.
     * @return string The calculated response as a binary string.
     */
    public function calculateLmResponse(
        HashCredentialInterface $hash_credential,
        $client_challenge,
        $server_challenge_nonce
    ) {
        $data_to_hash = ($server_challenge_nonce . $client_challenge);

        $keyed_hasher = $this->crypt_hasher_factory->build(
            static::KEYED_HASHER_ALGORITHM,
            $hash_credential->getValue()
        );

        $keyed_hash_result = $keyed_hasher->update($data_to_hash)->digest();

        return ($keyed_hash_result . $client_challenge);
    }

    /**
     * Encodes the "blob" (also known as "temp" in the official documentation).
     *
     * This value is used in calculating/generating both the NT response and the
     * base session key.
     *
     * @param DateTime $time The current time.
     * @param string $client_challenge A randomly generated 64-bit (8-byte)
     *   unsigned client-generated binary string.
     * @param string $target_info The "TargetInfo" data sent by the server and
     *   encoded in the server challenge.
     * @return string The encoded blob as a binary string.
     */
    public function encodeBlob(DateTime $time, $client_challenge, $target_info)
    {
        $blob_data = '';

        $blob_data .= pack('C', static::BLOB_RESPONSE_VERSION);
        $blob_data .= pack('C', static::BLOB_HIGHEST_RESPONSE_VERSION);
        $blob_data .= pack('x6');
        $blob_data .= pack('V', $time->getTimestamp());
        $blob_data .= pack('x4'); // Null-pad the timestamp, we don't need microsecond precision
        $blob_data .= pack('a8', $client_challenge);
        $blob_data .= pack('x4');
        $blob_data .= pack('a*', $target_info);
        $blob_data .= pack('x4');

        return $blob_data;
    }

    /**
     * Calculates the NT "proof" string (known as "NtProofStr" in the official
     * documentation).
     *
     * @param HashCredentialInterface $hash_credential The user's authentication
     *   NT hash credential.
     * @param string $server_challenge_nonce The 64-bit (8-byte) unsigned
     *   server-sent "nonce" (number used once) represented as a binary string.
     * @param string $blob The binary encoded "blob" string.
     * @return string The calculated NT "proof" string as a binary string.
     */
    public function calculateNtProofString(HashCredentialInterface $hash_credential, $server_challenge_nonce, $blob)
    {
        $data_to_hash = ($server_challenge_nonce . $blob);

        $keyed_hasher = $this->crypt_hasher_factory->build(
            static::KEYED_HASHER_ALGORITHM,
            $hash_credential->getValue()
        );

        return $keyed_hasher->update($data_to_hash)->digest();
    }
}
