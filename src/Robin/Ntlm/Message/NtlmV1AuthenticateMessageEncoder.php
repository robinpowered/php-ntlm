<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Message;

use InvalidArgumentException;
use Robin\Ntlm\Credential\CredentialInterface;
use Robin\Ntlm\Credential\HashCredentialInterface;
use Robin\Ntlm\Credential\HashType;
use Robin\Ntlm\Crypt\CipherMode;
use Robin\Ntlm\Crypt\Des\DesEncrypterInterface;
use Robin\Ntlm\Crypt\Hasher\HasherAlgorithm;
use Robin\Ntlm\Crypt\Hasher\HasherFactoryInterface;
use Robin\Ntlm\Crypt\Random\RandomByteGeneratorInterface;
use Robin\Ntlm\Encoding\EncodingConverterInterface;
use Robin\Ntlm\Hasher\HasherInterface;

/**
 * {@inheritDoc}
 *
 * Uses the NTLMv1 protocol for encoding the "AUTHENTICATE_MESSAGE".
 *
 * @link https://msdn.microsoft.com/en-us/library/cc236699.aspx
 */
class NtlmV1AuthenticateMessageEncoder extends AbstractAuthenticateMessageEncoder
{

    /**
     * Constants
     */

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
     * The expected {@link HasherAlgorithm} for the cryptographic hasher used
     * for extended session security.
     *
     * @type string
     */
    const EXTENDED_SESSION_SECURITY_HASHER_ALGORITHM = HasherAlgorithm::MD5;

    /**
     * The length of the challenge string used to create the NT response when
     * extended session security is used.
     *
     * @type int
     */
    const EXTENDED_SESSION_SECURITY_CHALLENGE_LENGTH = 8;


    /**
     * Properties
     */

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
     * The factory used to build a cryptographic hashing engine for generating
     * different hashes for various parts of the resulting message.
     *
     * @type HasherFactoryInterface
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
     * @param HasherInterface $lm_hasher Used to create the "LM hash".
     * @param HasherInterface $nt_hasher Used to create the "NT hash".
     * @param RandomByteGeneratorInterface $random_byte_generator Used to create
     *   encryption initialization vectors and to generate random client
     *   challenges for extended security support.
     * @param DesEncrypterInterface $des_encrypter Used to compute challenge
     *   responses for the different message hashes.
     * @param HasherFactoryInterface $crypt_hasher_factory Used to build a
     *   cryptographic hashing engine for generating different hashes for
     *   various parts of the resulting message.
     */
    public function __construct(
        EncodingConverterInterface $encoding_converter,
        HasherInterface $lm_hasher,
        HasherInterface $nt_hasher,
        RandomByteGeneratorInterface $random_byte_generator,
        DesEncrypterInterface $des_encrypter,
        HasherFactoryInterface $crypt_hasher_factory
    ) {
        parent::__construct($encoding_converter);

        $this->lm_hasher = $lm_hasher;
        $this->nt_hasher = $nt_hasher;
        $this->random_byte_generator = $random_byte_generator;
        $this->des_encrypter = $des_encrypter;
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
        $target_name = $server_challenge->getTargetName() ?: $nt_domain;

        $client_challenge = null;

        // If extended session security is negotiated
        if ((NegotiateFlag::NEGOTIATE_EXTENDED_SESSION_SECURITY & $negotiate_flags)
            === NegotiateFlag::NEGOTIATE_EXTENDED_SESSION_SECURITY) {
            // Generate a client challenge
            $client_challenge = $this->random_byte_generator->generate(static::CLIENT_CHALLENGE_LENGTH);
        }

        $lm_hash = null;
        $nt_hash = null;
        $lm_challenge_response = null;
        $nt_challenge_response = null;

        $calculate_lm_response = true;
        $calculate_nt_response = true;

        if ($credential->isPlaintext()) {
            $lm_hash = $this->lm_hasher->hash($credential);
            $nt_hash = $this->nt_hasher->hash($credential);
        } elseif ($credential instanceof HashCredentialInterface) {
            switch ($credential->getType()) {
                case HashType::LM:
                    $lm_hash = $credential;
                    $calculate_nt_response = false;
                    break;
                case HashType::NT_V1:
                    $nt_hash = $credential;
                    $calculate_lm_response = false;
                    break;
                default:
                    throw new InvalidArgumentException('Unsupported hash credential type');
            }
        }

        if (null !== $nt_hash && $calculate_nt_response) {
            $nt_challenge_response = $this->calculateNtResponse(
                $nt_hash,
                $client_challenge,
                $server_challenge_nonce
            );
        }

        if (null !== $lm_hash && $calculate_lm_response || null !== $client_challenge) {
            $lm_challenge_response = $this->calculateLmResponse(
                $lm_hash ?: $nt_hash,
                $client_challenge,
                $server_challenge_nonce
            );
        } else {
            // According to the spec, we're supposed to use the NT challenge response for the LM challenge response,
            // if an LM challenge response isn't calculated
            $lm_challenge_response = $nt_challenge_response;
        }

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
     * @param string|null $client_challenge A randomly generated 64-bit (8-byte)
     *   unsigned client-generated binary string.
     * @param string|null $server_challenge_nonce The 64-bit (8-byte) unsigned
     *   server-sent "nonce" (number used once) represented as a binary string.
     * @return string The calculated response as a binary string.
     */
    public function calculateLmResponse(
        HashCredentialInterface $hash_credential,
        $client_challenge = null,
        $server_challenge_nonce = null
    ) {
        // If we have a client challenge, extended session security must be negotiated
        if (null !== $client_challenge) {
            // Set the LM challenge response to the client challenge, null-padded to the expected length
            $lm_challenge_response = str_pad(
                $client_challenge,
                static::LM_RESPONSE_LENGTH,
                static::NULL_PAD_CHARACTER
            );
        } else {
            $lm_challenge_response = $this->calculateChallengeResponseData($hash_credential, $server_challenge_nonce);
        }

        return $lm_challenge_response;
    }

    /**
     * Calculates the NT response.
     *
     * @param HashCredentialInterface $hash_credential The user's authentication
     *   NT hash credential.
     * @param string|null $client_challenge A randomly generated 64-bit (8-byte)
     *   unsigned client-generated binary string.
     * @param string|null $server_challenge_nonce The 64-bit (8-byte) unsigned
     *   server-sent "nonce" (number used once) represented as a binary string.
     * @return string The calculated response as a binary string.
     */
    public function calculateNtResponse(
        HashCredentialInterface $hash_credential,
        $client_challenge = null,
        $server_challenge_nonce = null
    ) {
        // By default, our encryption data is our server challenge nonce
        $encryption_data = $server_challenge_nonce;

        // If we have a client challenge, extended session security must be negotiated
        if (null !== $client_challenge) {
            // Grab a hasher
            $extended_security_hasher = $this->crypt_hasher_factory->build(
                static::EXTENDED_SESSION_SECURITY_HASHER_ALGORITHM
            );

            // Concat the two challenge strings
            $nt_extended_security_challenge_source = $server_challenge_nonce . $client_challenge;

            $nt_extended_security_hash = $extended_security_hasher
                ->update($nt_extended_security_challenge_source)
                ->digest();

            // Our challenge is a substring of the resulting hash
            $nt_extended_security_challenge = substr(
                $nt_extended_security_hash,
                0,
                static::EXTENDED_SESSION_SECURITY_CHALLENGE_LENGTH
            );

            $encryption_data = $nt_extended_security_challenge;
        }

        return $this->calculateChallengeResponseData($hash_credential, $encryption_data);
    }

    /**
     * Calculates a response to a server challenge for a given credential hash.
     *
     * @param HashCredentialInterface $hash_credential The authentication
     *   credential hash to compute the response for.
     * @param string $data The binary string containing the previously
     *   calculated data to encrypt, depending on the session strategy.
     * @return string The calculated challenge response data as a binary string.
     */
    public function calculateChallengeResponseData(HashCredentialInterface $hash_credential, $data)
    {
        // Nul pad the credential hash to the full key size
        $padded_hash = str_pad($hash_credential->getValue(), static::DESL_FULL_KEY_LENGTH, static::NULL_PAD_CHARACTER);

        $key_blocks = str_split($padded_hash, static::DESL_KEY_BLOCK_SEGMENT_LENGTH);

        $binary_data = array_reduce(
            $key_blocks,
            function ($result, $key_block) use ($data) {
                return $result . $this->des_encrypter->encrypt(
                    $key_block,
                    $data,
                    CipherMode::ECB,
                    '' // DES-ECB expects a 0-byte-length initialization vector
                );
            },
            ''
        );

        return $binary_data;
    }
}
