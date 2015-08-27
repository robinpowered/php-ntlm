<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Message\Exception;

use Exception;
use UnexpectedValueException;

/**
 * An exception representing an invalid challenge message was detected.
 */
class InvalidChallengeMessageException extends UnexpectedValueException
{

    /**
     * Constants
     */

    /**
     * The default exception message.
     *
     * @type string
     */
    const DEFAULT_MESSAGE = 'Invalid challenge message';

    /**
     * The exception code for an invalid signature.
     *
     * @type int
     */
    const CODE_FOR_INVALID_SIGNATURE = 1;

    /**
     * The exception code for an invalid message type.
     *
     * @type int
     */
    const CODE_FOR_INVALID_MESSAGE_TYPE = 2;

    /**
     * The message for an invalid signature.
     *
     * @type string
     */
    const MESSAGE_FOR_INVALID_SIGNATURE = 'Invalid signature';

    /**
     * The message for an invalid message type.
     *
     * @type string
     */
    const MESSAGE_FOR_INVALID_MESSAGE_TYPE = 'Invalid message type';

    /**
     * The message extension format for providing reason information.
     *
     * @type string
     */
    const MESSAGE_EXTENSION_FOR_REASONS_FORMAT = ' with reasons: [%s]';

    /**
     * The "glue" used to merge the reason information for the message.
     *
     * @type string
     */
    const MESSAGE_REASON_GLUE = ', ';


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
     * The invalid challenge message.
     *
     * @type string
     */
    private $challenge_message;


    /**
     * Methods
     */

    /**
     * Create an exception instance for a given challenge message.
     *
     * @param string $challenge_message The invalid challenge message.
     * @param int $code The exception code.
     * @param Exception|null $previous A previous exception used for chaining.
     * @return static
     */
    public static function forChallengeMessage(
        $challenge_message,
        $code = 0,
        Exception $previous = null
    ) {
        $message = self::DEFAULT_MESSAGE;

        $reason_messages = [];

        if ((self::CODE_FOR_INVALID_SIGNATURE & $code) === self::CODE_FOR_INVALID_SIGNATURE) {
            $reason_messages[] = self::MESSAGE_FOR_INVALID_SIGNATURE;
        }

        if ((self::CODE_FOR_INVALID_MESSAGE_TYPE & $code) === self::CODE_FOR_INVALID_MESSAGE_TYPE) {
            $reason_messages[] = self::MESSAGE_FOR_INVALID_MESSAGE_TYPE;
        }

        $message .= sprintf(
            self::MESSAGE_EXTENSION_FOR_REASONS_FORMAT,
            implode(self::MESSAGE_REASON_GLUE, $reason_messages)
        );

        $instance = new static($message, $code, $previous);
        $instance->challenge_message = $challenge_message;

        return $instance;
    }

    /**
     * Gets the challenge message.
     *
     * @return string
     */
    public function getChallengeMessage()
    {
        return $this->challenge_message;
    }
}
