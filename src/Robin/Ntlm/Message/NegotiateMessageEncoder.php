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
class NegotiateMessageEncoder implements NegotiateMessageEncoderInterface
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
    const MESSAGE_TYPE = 0x00000001;

    /**
     * The character encoding used for "OEM" encoded values.
     *
     * @type string
     */
    const OEM_ENCODING = 'ASCII';


    /**
     * Properties
     */

    /**
     * The flags encoded in the message.
     *
     * PHP doesn't allow for compile-time bitwise operations, so we create an
     * array of integers here instead and we'll combine them later.
     *
     * @link https://wiki.php.net/rfc/const_scalar_exprs
     * @type int[]
     */
    private static $default_flags = [
        NegotiateFlag::NEGOTIATE_OEM,
        NegotiateFlag::REQUEST_TARGET,
        NegotiateFlag::NEGOTIATE_NTLM,
        NegotiateFlag::NEGOTIATE_ALWAYS_SIGN,
        NegotiateFlag::NEGOTIATE_EXTENDED_SESSION_SECURITY,
    ];

    /**
     * Used to convert encodings of strings before adding them to the message.
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
     * @param EncodingConverterInterface $encoding_converter Used to convert
     *   encodings of strings before adding them to the message.
     */
    public function __construct(EncodingConverterInterface $encoding_converter)
    {
        $this->encoding_converter = $encoding_converter;
    }

    /**
     * {@inheritDoc}
     */
    public function encode($nt_domain, $client_hostname, $negotiate_flags = null)
    {
        // Get our default negotiate flags if none were supplied
        $negotiate_flags = (null === $negotiate_flags) ? static::getDefaultNegotiateFlags() : $negotiate_flags;

        $nt_domain_supplied = false;
        $client_hostname_supplied = false;

        if ((NegotiateFlag::NEGOTIATE_OEM_DOMAIN_SUPPLIED & $negotiate_flags)
            === NegotiateFlag::NEGOTIATE_OEM_DOMAIN_SUPPLIED) {
            $nt_domain_supplied = true;

            $nt_domain = $this->encoding_converter->convert(
                strtoupper($nt_domain),
                static::OEM_ENCODING
            );
        } else {
            // If the domain supplied flag isn't set, set the domain to an empty byte string
            $nt_domain = '';
        }

        if ((NegotiateFlag::NEGOTIATE_OEM_WORKSTATION_SUPPLIED & $negotiate_flags)
            === NegotiateFlag::NEGOTIATE_OEM_WORKSTATION_SUPPLIED) {
            $client_hostname_supplied = true;

            $client_hostname = $this->encoding_converter->convert(
                strtoupper($client_hostname),
                static::OEM_ENCODING
            );
        } else {
            // If the hostname supplied flag isn't set, set the domain to an empty byte string
            $client_hostname = '';
        }

        // Determine and calculate some values
        $payload_offset = static::calculatePayloadOffset($negotiate_flags);
        $domain_name_length = strlen($nt_domain);
        $hostname_length = strlen($client_hostname);

        /**
         * Determine the payload offsets of the domain name and hostname
         *
         * The specification says that these offsets should be set to valid
         * locations even if the negotation flags don't contain the flags
         * denoting their inclusion, however some NTLM servers seem to throw a
         * bit of a fit if the offsets are set to non-zero values when the flags
         * don't denote their inclusion.
         *
         * So yea, we're breaking spec here to appease some seemingly old or
         * improper implementations. cURL does the same here.
         *
         * @link https://msdn.microsoft.com/en-us/library/cc236641.aspx
         * @link https://github.com/bagder/curl/blob/curl-7_46_0/lib/curl_ntlm_msgs.c#L364-L370
         */
        $domain_name_offset = $nt_domain_supplied ? $payload_offset : 0;
        $hostname_offset = $client_hostname_supplied ? ($payload_offset + $domain_name_length) : 0;

        // Prepare a binary string to be returned
        $binary_string = '';

        $binary_string .= static::SIGNATURE; // 8-byte signature
        $binary_string .= pack('V', static::MESSAGE_TYPE); // 32-bit unsigned little-endian

        $binary_string .= pack('V', $negotiate_flags); // 32-bit unsigned little-endian

        // Domain name fields: length; length; offset of the domain value from the beginning of the message
        $binary_string .= pack('v', $domain_name_length); // 16-bit unsigned little-endian
        $binary_string .= pack('v', $domain_name_length); // 16-bit unsigned little-endian
        $binary_string .= pack('V', $domain_name_offset); // 32-bit unsigned little-endian, 1st value in the payload

        // Hostname fields: length; length; offset of the hostname value from the beginning of the message
        $binary_string .= pack('v', $hostname_length); // 16-bit unsigned little-endian
        $binary_string .= pack('v', $hostname_length); // 16-bit unsigned little-endian
        $binary_string .= pack('V', $hostname_offset); // 32-bit unsigned little-endian, 2nd value

        // NOTE: Omitting the version data here. It's unnecessary.

        // Add our payload data
        $binary_string .= $nt_domain;
        $binary_string .= $client_hostname;

        return $binary_string;
    }

    /**
     * Gets the default negotiate flags.
     *
     * @return int The flags represented as a 32-bit unsigned integer.
     */
    public static function getDefaultNegotiateFlags()
    {
        return array_reduce(
            self::$default_flags,
            function ($result, $flag) {
                return ($result + $flag);
            },
            0
        );
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
        $offset += 4; // 32-bit Negotation flags

        $offset += 8; // 64-bit domain name field designator
        $offset += 8; // 64-bit client hostname field designator

        return $offset;
    }
}
