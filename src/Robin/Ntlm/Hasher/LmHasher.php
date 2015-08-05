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
use Robin\Ntlm\Crypt\Random\RandomByteGeneratorInterface;
use SplFixedArray;

/**
 * Uses the "LM hash" computation strategy to hash a {@link Password} credential
 * into a {@link HashCredentialInterface} of {@link HashType::LM}.
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
     * The length of the randomly generated binary string used for generating
     * each piece of the resulting hash.
     *
     * @type int
     */
    const RANDOM_BINARY_STRING_LENGTH = 8;

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
     * The generator used to generate cryptographically secure random bytes to
     * provide an initialization vector for encryption.
     *
     * @type RandomByteGeneratorInterface
     */
    private $random_byte_generator;


    /**
     * Methods
     */

    /**
     * Constructor
     *
     * @param DesEncrypterInterface $des_encrypter The DES encryption engine
     *   used to generate the hash.
     * @param RandomByteGeneratorInterface $random_byte_generator Used to
     *   generate cryptographically secure random bytes to provide an
     *   initialization vector for encryption.
     */
    public function __construct(
        DesEncrypterInterface $des_encrypter,
        RandomByteGeneratorInterface $random_byte_generator
    ) {
        $this->des_encrypter = $des_encrypter;
        $this->random_byte_generator = $random_byte_generator;
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
                $expanded = static::expand56BitKeyTo64BitKey($half);

                $result .= $this->des_encrypter->encrypt(
                    $expanded,
                    static::ENCRYPT_DATA_CONSTANT,
                    CipherMode::ECB,
                    $this->random_byte_generator->generate(static::RANDOM_BINARY_STRING_LENGTH)
                );

                return $result;
            },
            ''
        );

        return Hash::fromBinaryString($binary_hash, HashType::LM);
    }

    /**
     * Expand a 56-bit key to a full 64-bit key for DES encryption.
     *
     * @link http://php.net/manual/en/ref.hash.php#84587 Implementation basis.
     * @link https://github.com/jclulow/node-smbhash/blob/edc48e2b93067/lib/common.js Inspired by Joshua Clulow's work.
     * @param string $string_key The 56-bit key to expand
     * @return string
     */
    public static function expand56BitKeyTo64BitKey($string_key)
    {
        $byte_array_56 = new SplFixedArray(7);
        $byte_array_64 = new SplFixedArray(8);
        $key_64bit = '';

        // Get the byte value of each ASCII character in the string
        for ($i = 0; $i < $byte_array_56->getSize(); $i++) {
            $byte_array_56[$i] = isset($string_key[$i]) ? ord($string_key[$i]) : 0;
        }

        $byte_array_64[0] = $byte_array_56[0] & 254;
        $byte_array_64[1] = ($byte_array_56[0] << 7) | ($byte_array_56[1] >> 1);
        $byte_array_64[2] = ($byte_array_56[1] << 6) | ($byte_array_56[2] >> 2);
        $byte_array_64[3] = ($byte_array_56[2] << 5) | ($byte_array_56[3] >> 3);
        $byte_array_64[4] = ($byte_array_56[3] << 4) | ($byte_array_56[4] >> 4);
        $byte_array_64[5] = ($byte_array_56[4] << 3) | ($byte_array_56[5] >> 5);
        $byte_array_64[6] = ($byte_array_56[5] << 2) | ($byte_array_56[6] >> 6);
        $byte_array_64[7] = $byte_array_56[6] << 1;

        foreach ($byte_array_64 as $byte_val) {
            $key_64bit = chr($byte_val);
        }

        return $key_64bit;
    }
}
