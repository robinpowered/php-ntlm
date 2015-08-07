<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Hasher;

use Robin\Ntlm\Credential\Hash;
use Robin\Ntlm\Credential\HashType;
use Robin\Ntlm\Credential\Password;
use Robin\Ntlm\Crypt\Hasher\HasherAlgorithm;
use Robin\Ntlm\Crypt\Hasher\HasherFactoryInterface;
use Robin\Ntlm\Encoding\EncodingConverterInterface;

/**
 * Uses the "NT hash" computation strategy to hash a {@link Password} credential
 * into a {@link HashCredentialInterface} of {@link HashType::NT_V1}.
 *
 * Known in internal Microsoft documentation as the "NTOWF" function.
 *
 * @link http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/[MS-NLMP].pdf
 * @link https://msdn.microsoft.com/en-us/library/cc236699.aspx
 */
class NtV1Hasher implements HasherInterface
{

    /**
     * Constants
     */

    /**
     * The expected {@link HasherAlgorithm} for the cryptographic hasher.
     *
     * @type string
     */
    const EXPECTED_HASHER_ALGORITHM = HasherAlgorithm::MD4;

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
     * The factory used to build a cryptographic hashing engine for generating
     * the resulting hash.
     *
     * @type HasherFactoryInterface
     */
    private $crypt_hasher_factory;

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
     * @param HasherFactoryInterface $crypt_hasher_factory The factory used to
     *   build a cryptographic hashing engine for generating the resulting hash.
     * @param EncodingConverterInterface $encoding_converter Used to convert
     *   encodings of the input credential for hashing.
     */
    public function __construct(
        HasherFactoryInterface $crypt_hasher_factory,
        EncodingConverterInterface $encoding_converter
    ) {
        $this->crypt_hasher_factory = $crypt_hasher_factory;
        $this->encoding_converter = $encoding_converter;
    }

    /**
     * {@inheritDoc}
     */
    public function hash(Password $password)
    {
        $unicode_password_string = $this->encoding_converter->convert(
            $password->getValue(),
            static::HASH_SOURCE_ENCODING
        );

        $crypt_hasher = $this->crypt_hasher_factory->build(static::EXPECTED_HASHER_ALGORITHM);

        $binary_hash = $crypt_hasher->update($unicode_password_string)->digest();

        return Hash::fromBinaryString($binary_hash, HashType::NT_V1);
    }
}
