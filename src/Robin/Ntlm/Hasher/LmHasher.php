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
use Robin\Ntlm\Crypt\CipherMode;
use Robin\Ntlm\Crypt\Des\DesEncrypterInterface;

/**
 * Uses the "LM hash" computation strategy to hash a {@link Password} credential
 * into a {@link HashCredentialInterface} of {@link HashType::LM}.
 *
 * Known in internal Microsoft documentation as the "LMOWF" function.
 *
 * @link http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/[MS-NLMP].pdf
 * @link https://msdn.microsoft.com/en-us/library/cc236699.aspx
 */
class LmHasher implements HasherInterface
{

    /**
     * Constants
     */

    /**
     * The maximum length of a provided string password.
     *
     * @type int
     */
    const MAXIMUM_PASSWORD_LENGTH = 14;

    /**
     * The character used for null padding.
     *
     * @type string
     */
    const NULL_PAD_CHARACTER = "\0";

    /**
     * The length of the sliced passwords, in bytes.
     *
     * @type int
     */
    const PASSWORD_SLICE_LENGTH = 7;

    /**
     * The constant known ASCII text to encrypt with the generated keys.
     *
     * @link https://tools.ietf.org/html/rfc2433#appendix-A.3
     * @link http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/[MS-NLMP].pdf
     * @link https://msdn.microsoft.com/en-us/library/cc236699.aspx
     * @type string
     */
    const ENCRYPT_DATA_CONSTANT = 'KGS!@#$%';


    /**
     * Properties
     */

    /**
     * The DES encryption engine used to generate the hash.
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
     * @param DesEncrypterInterface $des_encrypter The DES encryption engine
     *   used to generate the hash.
     */
    public function __construct(DesEncrypterInterface $des_encrypter)
    {
        $this->des_encrypter = $des_encrypter;
    }

    /**
     * {@inheritDoc}
     *
     * NOTE: String operations are intentionally not "Unicode-aware", as the
     * LM Hash encryption algorithm is intended to operate on raw "bytes",
     * regardless of the byte-width of the character's encoding.
     */
    public function hash(Password $password)
    {
        $string_password = substr($password->getValue(), 0, static::MAXIMUM_PASSWORD_LENGTH);
        $string_password = strtoupper($string_password);

        // Null-pad the string to the maximum length
        $string_password = str_pad($string_password, static::MAXIMUM_PASSWORD_LENGTH, static::NULL_PAD_CHARACTER);

        $halves = str_split($string_password, static::PASSWORD_SLICE_LENGTH);

        // Encrypt and concatenate each half
        $binary_hash = array_reduce(
            $halves,
            function ($result, $half) {
                return $result . $this->des_encrypter->encrypt(
                    $half,
                    static::ENCRYPT_DATA_CONSTANT,
                    CipherMode::ECB,
                    '' // DES-ECB expects a 0-byte-length initialization vector
                );
            },
            ''
        );

        return Hash::fromBinaryString($binary_hash, HashType::LM);
    }
}
