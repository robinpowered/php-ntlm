<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Encoding;

use Robin\Ntlm\Encoding\Exception\EncodingConversionFailureException;
use Robin\Ntlm\Encoding\Exception\EncodingDetectionException;

/**
 * Converts between different character encodings.
 */
interface EncodingConverterInterface
{

    /**
     * Converts a string's character encoding.
     *
     * @param string $string The string to convert the encoding of.
     * @param string $to_encoding The desired encoding of the resulting string.
     * @param string|null $from_encoding The encoding of the input string. If
     *   left as `null`, implementations may decide whether they use a default
     *   encoding or attempt to detect the encoding of the input string.
     * @return string The result string with the desired character encoding.
     * @throws EncodingDetectionException If encoding detection fails.
     * @throws EncodingConversionFailureException If the conversion fails.
     */
    public function convert($string, $to_encoding, $from_encoding = null);
}
