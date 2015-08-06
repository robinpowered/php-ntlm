<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Hasher;

use InvalidArgumentException;
use Robin\Ntlm\Credential\Hash;
use Robin\Ntlm\Credential\HashType;
use Robin\Ntlm\Credential\Password;
use Robin\Ntlm\Crypt\Hasher\HasherAlgorithm;
use Robin\Ntlm\Crypt\Hasher\KeyedHasherFactoryInterface;
use Robin\Ntlm\Encoding\EncodingConverterInterface;

/**
 * Uses the "NT hash" computation strategy to hash a {@link Password} credential
 * and user-identifying meta-data into a {@link HashCredentialInterface} of
 * {@link HashType::NT_V2}.
 *
 * Known in internal Microsoft documentation as the "NTOWFv2" function.
 *
 * @link http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/[MS-NLMP].pdf
 * @link https://msdn.microsoft.com/en-us/library/cc236700.aspx
 */
class NtV2Hasher implements IdentityMetaHasherInterface
{

    /**
     * Constants
     */

    /**
     * The expected {@link HasherAlgorithm} for the cryptographic hasher.
     *
     * @type string
     */
    const EXPECTED_HASHER_ALGORITHM = HasherAlgorithm::MD5;

    /**
     * The character encoding that the hash source (input credential) should be
     * encoded in for consistent hashing results.
     *
     * @type string
     */
    const HASH_SOURCE_ENCODING = 'UTF-16LE';


    /**
     * Properties
     */

    /**
     * The NTv1 hasher used to create the basis of the NTv2 hash.
     *
     * @type NtV1Hasher
     */
    private $nt_v1_hasher;

    /**
     * The factory used to build a keyed hasher for an HMAC hashing digest.
     *
     * @type KeyedHasherFactoryInterface
     */
    private $keyed_hasher_factory;

    /**
     * Used to convert encodings of the input credential for hashing.
     *
     * @type EncodingConverterInterface
     */
    private $encoding_converter;


    /**
     * Methods
     */

    /**
     * Constructor
     *
     * @param NtV1Hasher $nt_v1_hasher The NTv1 hasher used to create the basis
     *   of the NTv2 hash.
     * @param KeyedHasherFactoryInterface $keyed_hasher_factory The factory used
     *   to build a keyed hasher for an HMAC hashing digest.
     * @param EncodingConverterInterface $encoding_converter Used to convert
     *   encodings of the input credential for hashing.
     */
    public function __construct(
        NtV1Hasher $nt_v1_hasher,
        KeyedHasherFactoryInterface $keyed_hasher_factory,
        EncodingConverterInterface $encoding_converter
    ) {
        $this->nt_v1_hasher = $nt_v1_hasher;
        $this->keyed_hasher_factory = $keyed_hasher_factory;
        $this->encoding_converter = $encoding_converter;
    }

    /**
     * {@inheritDoc}
     */
    public function hash(Password $password, $username, $domain_name)
    {
        $nt_v1_hash = $this->nt_v1_hasher->hash($password);

        $hmac_hasher = $this->keyed_hasher_factory->build(static::EXPECTED_HASHER_ALGORITHM, $nt_v1_hash);

        $data_to_hash = $this->encoding_converter->convert(
            (strtoupper($username) . $domain_name),
            static::HASH_SOURCE_ENCODING
        );

        $binary_hash = $hmac_hasher->update($data_to_hash)->digest();

        return Hash::fromBinaryString($binary_hash, HashType::NT_V2);
    }
}
