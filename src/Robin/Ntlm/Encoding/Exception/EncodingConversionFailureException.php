<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Encoding\Exception;

use Exception;
use UnexpectedValueException;

/**
 * An exception representing a failure to convert encodings.
 */
class EncodingConversionFailureException extends UnexpectedValueException
{

    /**
     * Constants
     */

    /**
     * The default exception message.
     *
     * @type string
     */
    const DEFAULT_MESSAGE = 'Failed to convert encoding';

    /**
     * The exception code for an exception with a given string context.
     *
     * @type int
     */
    const CODE_FOR_STRING = 1;

    /**
     * The exception code for an exception with a given string context and
     * encoding information.
     *
     * @type int
     */
    const CODE_FOR_STRING_AND_ENCODING_INFO = 2;

    /**
     * The message extension format for providing a string context.
     *
     * @type string
     */
    const MESSAGE_EXTENSION_FOR_STRING_FORMAT = ' of string "%s"';

    /**
     * The message extension format for providing encoding information.
     *
     * @type string
     */
    const MESSAGE_EXTENSION_FOR_ENCODING_INFO_FORMAT = ' from encoding "%s" and to encoding "%s"';


    /**
     * Properties
     */

    /**
     * {@inheritDoc}
     *
     * @type string
     */
    protected $message = self::DEFAULT_MESSAGE;


    /**
     * Methods
     */

    /**
     * Creates an exception instance for a given string.
     *
     * @param string $string The string that failed to convert the encoding of.
     * @param int $code The exception code.
     * @param Exception|null $previous A previous exception used for chaining.
     * @return static
     */
    public static function forString($string, $code = self::CODE_FOR_STRING, Exception $previous = null)
    {
        $message = self::DEFAULT_MESSAGE . sprintf(self::MESSAGE_EXTENSION_FOR_STRING_FORMAT, $string);

        return new static($message, $code, $previous);
    }

    /**
     * Creates an exception instance for a given string and encoding information.
     *
     * @param string $string The string that failed to convert the encoding of.
     * @param string $from_encoding The encoding that the string was being
     *   converted from.
     * @param string $to_encoding The encoding that the string was being
     *   converted to.
     * @param int $code The exception code.
     * @param Exception|null $previous A previous exception used for chaining.
     * @return static
     */
    public static function forStringAndEncodings(
        $string,
        $from_encoding,
        $to_encoding,
        $code = self::CODE_FOR_STRING_AND_ENCODING_INFO,
        Exception $previous = null
    ) {
        $message = self::DEFAULT_MESSAGE
            . sprintf(self::MESSAGE_EXTENSION_FOR_STRING_FORMAT, $string)
            . sprintf(self::MESSAGE_EXTENSION_FOR_ENCODING_INFO_FORMAT, $from_encoding, $to_encoding);

        return new static($message, $code, $previous);
    }
}
