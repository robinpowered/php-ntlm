<?php
/**
 * Robin NTLM
 *
 * @copyright 2015 Robin Powered, Inc.
 * @link https://robinpowered.com/
 */

namespace Robin\Ntlm\Message;

/**
 * Constant definitions of flags used during NTLM message encoding/decoding.
 *
 * @link https://msdn.microsoft.com/en-us/library/cc236650.aspx
 */
class NegotiateFlag
{

    /**
     * Signifies a Unicode character set should be used in the message.
     *
     * Known as "NTLMSSP_NEGOTIATE_UNICODE" in the specification documentation.
     *
     * @type int
     */
    const NEGOTIATE_UNICODE = 0x00000001;

    /**
     * Signifies the OEM character set should be used in the message.
     *
     * Known as "NTLM_NEGOTIATE_OEM" in the specification documentation.
     *
     * @type int
     */
    const NEGOTIATE_OEM = 0x00000002;

    /**
     * Signifies that the {@link self::TARGET_TYPE_SERVER} field of the
     * "CHALLENGE_MESSAGE" must be supplied.
     *
     * Known as "NTLMSSP_REQUEST_TARGET" in the specification documentation.
     *
     * @type int
     */
    const REQUEST_TARGET = 0x00000004;

    /**
     * An unused bit. Must be set to zero.
     *
     * @type int
     */
    const UNUSED_10 = 0x00000008;

    /**
     * Signifies a request for session key negotiation for message signatures.
     *
     * Known as "NTLMSSP_NEGOTIATE_SIGN" in the specification documentation.
     *
     * @type int
     */
    const NEGOTIATE_SIGN = 0x00000010;

    /**
     * Signifies a request for session key negotiation for message
     * "confidentiality" (encryption).
     *
     * Known as "NTLMSSP_NEGOTIATE_SEAL" in the specification documentation.
     *
     * @type int
     */
    const NEGOTIATE_SEAL = 0x00000020;

    /**
     * Signifies that connectionless authentication should be used.
     *
     * Known as "NTLMSSP_NEGOTIATE_DATAGRAM" in the specification documentation.
     *
     * @type int
     */
    const NEGOTIATE_DATAGRAM = 0x00000040;

    /**
     * Signifies that LM session key computation should be used in the message.
     *
     * Known as "NTLMSSP_NEGOTIATE_LM_KEY" in the specification documentation.
     *
     * @type int
     */
    const NEGOTIATE_LAN_MANAGER_KEY = 0x00000080;

    /**
     * An unused bit. Must be set to zero.
     *
     * @type int
     */
    const UNUSED_9 = 0x00000100;

    /**
     * Signifies that the NTLM v1 session security protocol should be used.
     *
     * Known as "NTLMSSP_NEGOTIATE_NTLM" in the specification documentation.
     *
     * @type int
     */
    const NEGOTIATE_NTLM = 0x00000200;

    /**
     * An unused bit. Must be set to zero.
     *
     * @type int
     */
    const UNUSED_8 = 0x00000400;

    /**
     * Signifies that the connection should be anonymous.
     *
     * @type int
     */
    const ANONYMOUS = 0x00000800;

    /**
     * Signifies that a domain name is provided.
     *
     * Known as "NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED" in the specification
     * documentation.
     *
     * @type int
     */
    const NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000;

    /**
     * Signifies that the "Workstation" field is provided.
     *
     * Known as "NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED" in the
     * specification documentation.
     *
     * @type int
     */
    const NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000;

    /**
     * An unused bit. Must be set to zero.
     *
     * @type int
     */
    const UNUSED_7 = 0x00004000;

    /**
     * Signifies that the message should contain a signature block.
     *
     * Known as "NTLMSSP_NEGOTIATE_ALWAYS_SIGN" in the specification
     * documentation.
     *
     * @type int
     */
    const NEGOTIATE_ALWAYS_SIGN = 0x00008000;

    /**
     * Signifies that the "TargetName" field must be a domain.
     *
     * Known as "NTLMSSP_TARGET_TYPE_DOMAIN" in the specification documentation.
     *
     * @type int
     */
    const TARGET_TYPE_DOMAIN = 0x00010000;

    /**
     * Signifies that the "TargetName" field must be a server.
     *
     * Known as "NTLMSSP_TARGET_TYPE_SERVER" in the specification documentation.
     *
     * @type int
     */
    const TARGET_TYPE_SERVER = 0x00020000;

    /**
     * An unused bit. Must be set to zero.
     *
     * @type int
     */
    const UNUSED_6 = 0x00040000;

    /**
     * Signifies that the NTLM v2 session security protocol should be used.
     *
     * Known as "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY" in the
     * specification documentation.
     *
     * @type int
     */
    const NEGOTIATE_EXTENDED_SECURITY = 0x00080000;

    /**
     * Signifies that an "identify level token" should be used in the message.
     *
     * Known as "NTLMSSP_NEGOTIATE_IDENTIFY" in the specification documentation.
     *
     * @type int
     */
    const NEGOTIATE_IDENTIFY = 0x00100000;

    /**
     * An unused bit. Must be set to zero.
     *
     * @type int
     */
    const UNUSED_5 = 0x00200000;

    /**
     * Signifies that an "LMOWF" hash should be used.
     *
     * Known as "NTLMSSP_REQUEST_NON_NT_SESSION_KEY" in the specification
     * documentation.
     *
     * @type int
     */
    const REQUEST_NON_NT_SESSION_KEY = 0x00400000;

    /**
     * Signifies that the "TargetInfo" field is provided.
     *
     * Known as "NTLMSSP_NEGOTIATE_TARGET_INFO" in the specification
     * documentation.
     *
     * @type int
     */
    const NEGOTIATE_TARGET_INFO = 0x00800000;

    /**
     * An unused bit. Must be set to zero.
     *
     * @type int
     */
    const UNUSED_4 = 0x01000000;

    /**
     * Signifies the protocol version number.
     *
     * Known as "NTLMSSP_NEGOTIATE_VERSION" in the specification documentation.
     *
     * @type int
     */
    const NEGOTIATE_VERSION = 0x02000000;

    /**
     * An unused bit. Must be set to zero.
     *
     * @type int
     */
    const UNUSED_3 = 0x04000000;

    /**
     * An unused bit. Must be set to zero.
     *
     * @type int
     */
    const UNUSED_2 = 0x08000000;

    /**
     * An unused bit. Must be set to zero.
     *
     * @type int
     */
    const UNUSED_1 = 0x10000000;

    /**
     * Signifies that a 128-bit session key should be used.
     *
     * Known as "NTLMSSP_NEGOTIATE_128" in the specification documentation.
     *
     * @type int
     */
    const NEGOTIATE_128 = 0x20000000;

    /**
     * Signifies that an explicit key exchange should be used.
     *
     * Known as "NTLMSSP_NEGOTIATE_KEY_EXCH" in the specification documentation.
     *
     * @type int
     */
    const NEGOTIATE_KEY_EXCHANGE = 0x40000000;

    /**
     * Signifies that a 56-bit session key should be used.
     *
     * Known as "NTLMSSP_NEGOTIATE_56" in the specification documentation.
     *
     * @type int
     */
    const NEGOTIATE_56 = 0x80000000;
}
