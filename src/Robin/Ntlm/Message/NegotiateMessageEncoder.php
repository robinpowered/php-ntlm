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
    private static $flags = [
        NegotiateFlag::NEGOTIATE_UNICODE,
        NegotiateFlag::NEGOTIATE_OEM,
        NegotiateFlag::REQUEST_TARGET,
        NegotiateFlag::NEGOTIATE_NTLM,
        NegotiateFlag::NEGOTIATE_OEM_DOMAIN_SUPPLIED,
        NegotiateFlag::NEGOTIATE_OEM_WORKSTATION_SUPPLIED,
        NegotiateFlag::NEGOTIATE_ALWAYS_SIGN,
        NegotiateFlag::NEGOTIATE_EXTENDED_SESSION_SECURITY,
        NegotiateFlag::NEGOTIATE_128,
        NegotiateFlag::NEGOTIATE_56,
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
    public function encode($nt_domain, $client_hostname)
    {
        // Convert our provided values to proper encoding
        $nt_domain = $this->encoding_converter->convert(
            strtoupper($nt_domain),
            static::OEM_ENCODING
        );
        $client_hostname = $this->encoding_converter->convert(
            strtoupper($client_hostname),
            static::OEM_ENCODING
        );

        // Determine and calculate some values
        $negotiate_flags = $this->getNegotiateFlags();
        $payload_offset = static::calculatePayloadOffset($negotiate_flags);
        $domain_name_length = strlen($nt_domain);
        $hostname_length = strlen($client_hostname);

        // Prepare a binary string to be returned
        $binary_string = '';

        $binary_string .= static::SIGNATURE; // 8-byte signature
        $binary_string .= pack('V', static::MESSAGE_TYPE); // 32-bit unsigned little-endian

        $binary_string .= pack('V', $negotiate_flags); // 32-bit unsigned little-endian

        // Domain name fields: length; length; offset of the domain value from the beginning of the message
        $binary_string .= pack('v', $domain_name_length); // 16-bit unsigned little-endian
        $binary_string .= pack('v', $domain_name_length); // 16-bit unsigned little-endian
        $binary_string .= pack('V', $payload_offset); // 32-bit unsigned little-endian, 1st value in the payload

        // Hostname fields: length; length; offset of the hostname value from the beginning of the message
        $binary_string .= pack('v', $hostname_length); // 16-bit unsigned little-endian
        $binary_string .= pack('v', $hostname_length); // 16-bit unsigned little-endian
        $binary_string .= pack('V', $payload_offset + $domain_name_length); // 32-bit unsigned little-endian, 2nd value

        // NOTE: Omitting the version data here. It's unnecessary.

        // Add our payload data
        $binary_string .= $nt_domain;
        $binary_string .= $client_hostname;

        return $binary_string;
    }

    /**
     * Gets the negotiate flags.
     *
     * @return int The flags represented as a 32-bit unsigned integer.
     */
    public function getNegotiateFlags()
    {
        return array_reduce(
            self::$flags,
            function ($result, $flag) {
                return ($result + $flag);
            },
            0
        );
    }

    /**
     * Calculates the offset of the message "Payload" from the most-significant bit.
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

        if ((NegotiateFlag::NEGOTIATE_OEM_DOMAIN_SUPPLIED & $negotiate_flags)
            === NegotiateFlag::NEGOTIATE_OEM_DOMAIN_SUPPLIED) {
            $offset += 8; // 64-bit domain name field designator
        }

        if ((NegotiateFlag::NEGOTIATE_OEM_WORKSTATION_SUPPLIED & $negotiate_flags)
            === NegotiateFlag::NEGOTIATE_OEM_WORKSTATION_SUPPLIED) {
            $offset += 8; // 64-bit client hostname field designator
        }

        if ((NegotiateFlag::NEGOTIATE_VERSION & $negotiate_flags)
            === NegotiateFlag::NEGOTIATE_VERSION) {
            $offset += 8; // 64-bit version designator
        }

        return $offset;
    }
}
