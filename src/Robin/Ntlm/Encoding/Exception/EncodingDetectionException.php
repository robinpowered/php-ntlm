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
 * An exception representing an inability to detect encoding of a string or the
 * current running system.
 */
class EncodingDetectionException extends UnexpectedValueException
{

    /**
     * Constants
     */

    /**
     * The default exception message.
     *
     * @type string
     */
    const DEFAULT_MESSAGE = 'Unable to detect encoding';

    /**
     * The exception code for an inability to detecting the system's encoding.
     *
     * @type int
     */
    const CODE_FOR_SYSTEM = 1;

    /**
     * The exception code for an exception with a given string context.
     *
     * @type int
     */
    const CODE_FOR_STRING = 2;

    /**
     * The message extension for the current system.
     *
     * @type string
     */
    const MESSAGE_EXTENSION_FOR_SYSTEM = ' of the current system';

    /**
     * The message extension format for providing a string context.
     *
     * @type string
     */
    const MESSAGE_EXTENSION_FOR_STRING_FORMAT = ' of string "%s"';


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
     * Create an exception instance for the current system.
     *
     * @param int $code The exception code.
     * @param Exception|null $previous A previous exception used for chaining.
     * @return static
     */
    public static function forCurrentSystem($code = self::CODE_FOR_SYSTEM, Exception $previous = null)
    {
        $message = self::DEFAULT_MESSAGE . self::MESSAGE_EXTENSION_FOR_SYSTEM;

        return new static($message, $code, $previous);
    }

    /**
     * Create an exception instance for a given string.
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
}
