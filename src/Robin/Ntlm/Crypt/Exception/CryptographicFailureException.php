<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Crypt\Exception;

use Exception;
use UnexpectedValueException;

/**
 * An exception representing a cryptographic operation failed.
 */
class CryptographicFailureException extends UnexpectedValueException
{

    /**
     * Constants
     */

    /**
     * The default exception message.
     *
     * @type string
     */
    const DEFAULT_MESSAGE = 'Cryptographic operation failed';

    /**
     * The exception code for an encryption failure.
     *
     * @type int
     */
    const CODE_FOR_ENCRYPTION_FAILURE = 1;

    /**
     * The exception code for a random data generation failure.
     *
     * @type int
     */
    const CODE_FOR_RANDOM_DATA_GENERATION_FAILURE = 2;

    /**
     * The message for an encryption failure.
     *
     * @type string
     */
    const MESSAGE_FOR_ENCRYPTION_FAILURE = 'Failed to encrypt';

    /**
     * The message for a random data generation failure.
     *
     * @type string
     */
    const MESSAGE_FOR_RANDOM_DATA_GENERATION_FAILURE = 'Failed to generate random data';


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
     * Creates an exception instance for a given reason code.
     *
     * This automatically maps a reason message to the given reason code.
     *
     * @param int $code The exception/reason code.
     * @param Exception|null $previous A previous exception used for chaining.
     * @return static
     */
    public static function forReasonCode($code = 0, Exception $previous = null)
    {
        switch ($code) {
            case self::CODE_FOR_ENCRYPTION_FAILURE:
                $message = self::MESSAGE_FOR_ENCRYPTION_FAILURE;
                break;
            case self::CODE_FOR_RANDOM_DATA_GENERATION_FAILURE:
                $message = self::MESSAGE_FOR_RANDOM_DATA_GENERATION_FAILURE;
                break;
            default:
                $message = self::DEFAULT_MESSAGE;
        }

        return new static($message, $code, $previous);
    }
}
