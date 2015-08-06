<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Encoding;

use UnexpectedValueException;

/**
 * {@inheritDoc}
 *
 * Implemented using the "mbstring" extension (`ext-mbstring`).
 *
 * @link http://php.net/manual/en/book.mbstring.php
 */
class MbstringEncodingConverter implements EncodingConverterInterface
{

    /**
     * Constants
     */

    /**
     * The default detection value.
     *
     * @type bool
     */
    const DEFAULT_DETECT = true;


    /**
     * Properties
     */

    /**
     * Whether or not to try and automatically detect the encoding of input
     * strings when an explicit encoding isn't provided.
     *
     * @type bool
     */
    private $detect = self::DEFAULT_DETECT;


    /**
     * Methods
     */

    /**
     * Constructor
     *
     * @param bool $detect Whether or not to try and automatically detect the
     *   encoding of input strings when an explicit encoding isn't provided.
     */
    public function __construct($detect = self::DEFAULT_DETECT)
    {
        $this->detect = $detect;
    }

    /**
     * {@inheritDoc}
     *
     * A list of supported encodings can be determined by running
     * {@link http://php.net/manual/en/function.mb-list-encodings.php `mb_list_encodings()`}
     */
    public function convert($string, $to_encoding, $from_encoding = null)
    {
        $from_encoding = (null !== $from_encoding) ? $from_encoding : $this->resolveInputEncoding($string);

        $result = mb_convert_encoding($string, $to_encoding, $from_encoding);

        if (false === $result) {
            throw new UnexpectedValueException(
                sprintf(
                    'Failed to convert the encoding of string "%s", from encoding "%s" and to encoding "%s"',
                    $string,
                    $from_encoding,
                    $to_encoding
                )
            );
        }

        return $result;
    }

    /**
     * Resolves the input encoding of a given string.
     *
     * May attempt to detect the encoding, or may fall back to using the
     * internal encoding.
     *
     * @param string $string The input string to resolve encoding from.
     * @return string The encoding "name".
     */
    private function resolveInputEncoding($string)
    {
        $encoding = null;

        if (null === $encoding) {
            if ($this->detect) {
                $encoding = mb_detect_encoding($string, null, true);
            }

            // Fall back to the internal encoding
            if (false === $encoding || null === $encoding) {
                $encoding = mb_internal_encoding();
            }
        }

        if (false === $encoding || null === $encoding) {
            throw new UnexpectedValueException('Unable to detect encoding');
        }

        return $encoding;
    }
}
