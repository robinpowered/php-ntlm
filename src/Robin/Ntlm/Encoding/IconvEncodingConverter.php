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
use UnexpectedValueException;

/**
 * {@inheritDoc}
 *
 * Implemented using the "iconv" extension (`ext-iconv`).
 *
 * @link http://php.net/manual/en/book.iconv.php
 */
class IconvEncodingConverter implements EncodingConverterInterface
{

    /**
     * Constants
     */

    /**
     * The string flag used to retrieve the internal encoding with iconv.
     *
     * @link http://php.net/manual/en/function.iconv-get-encoding.php
     * @type string
     */
    const ICONV_INTERNAL_ENCODING_FLAG = 'internal_encoding';


    /**
     * Methods
     */

    /**
     * {@inheritDoc}
     */
    public function convert($string, $to_encoding, $from_encoding = null)
    {
        $from_encoding = (null !== $from_encoding) ? $from_encoding : static::getInternalEncoding();

        $result = iconv($from_encoding, $to_encoding, $string);

        if (false === $result) {
            throw EncodingConversionFailureException::forStringAndEncodings($string, $from_encoding, $to_encoding);
        }

        return $result;
    }

    /**
     * Gets the current internal encoding.
     *
     * @return string
     */
    public static function getInternalEncoding()
    {
        $encoding = iconv_get_encoding(static::ICONV_INTERNAL_ENCODING_FLAG);

        if (false === $encoding) {
            throw EncodingDetectionException::forCurrentSystem();
        }

        return $encoding;
    }
}
