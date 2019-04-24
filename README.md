# PHP NTLM

[![Build Status](https://img.shields.io/travis/robinpowered/php-ntlm.svg?style=flat)](https://travis-ci.org/robinpowered/php-ntlm)
[![Quality Score](https://img.shields.io/scrutinizer/g/robinpowered/php-ntlm.svg?style=flat)](https://scrutinizer-ci.com/g/robinpowered/php-ntlm/)
[![Latest Stable Version](https://img.shields.io/github/release/robinpowered/php-ntlm.svg?style=flat)](https://github.com/robinpowered/php-ntlm/releases)

PHP-NTLM is a library that handles the encoding and decoding of messages used in the challenge-and-response flow of the
NTLM authentication protocol, while also providing separate injectable credential hashing mechanisms to allow for a more
secure version of a credential for storage (rather than storing passwords in "plain-text").


## Features

- NTLM client message encoding and decoding
- Multiple text-encoding native-extensions supported
- LM, NTv1, and NTv2 hashing algorithms supported


## Requirements

- 64-bit PHP runtime (NTLM negotiation bit flags extend beyond the 32-bit integer size)
- PHP `>=7.1.0`


## Installation

1. [Get Composer][composer-website]
2. Add `robinpowered/php-ntlm` to your Composer required dependencies: `composer require robinpowered/php-ntlm`
3. Include the [Composer autoloader][composer-documentation-autoloading]


## Example Usage

```php
// Using Guzzle
$client = new Client();
$request = new Request('get', 'https://my-exchange-url.com');
$user_name = 'user_name';
$password = 'password';
$target_name = 'target_name';
$host_name = 'host_name';

$encoding_converter = new MbstringEncodingConverter();
$random_byte_generator = new NativeRandomByteGenerator();
$hasher_factory = HasherFactory::createWithDetectedSupportedAlgorithms();

$negotiate_message_encoder = new NegotiateMessageEncoder($encoding_converter);
$challenge_message_decoder = new ChallengeMessageDecoder();

$keyed_hasher_factory = KeyedHasherFactory::createWithDetectedSupportedAlgorithms();

$nt1_hasher = new NtV1Hasher($hasher_factory, $encoding_converter);
$nt2_hasher = new NtV2Hasher($nt1_hasher, $keyed_hasher_factory, $encoding_converter);

$authenticate_message_encoder = new NtlmV2AuthenticateMessageEncoder(
    $encoding_converter,
    $nt2_hasher,
    $random_byte_generator,
    $keyed_hasher_factory
);

$negotiate_message = $negotiate_message_encoder->encode(
    $target_name,
    $host_name
);

// Send negotiate message
$request->setHeader('Authorization', sprintf('NTLM %s', base64_encode($negotiate_message)));
$response = $client->send($request);

// Decode returned challenge message
$authenticate_headers = $response->getHeaderAsArray('WWW-Authenticate');
foreach ($authenticate_headers as $header_string) {
    $ntlm_matches = preg_match('/NTLM( (.*))?/', $header_string, $ntlm_header);

    if (0 < $ntlm_matches && isset($ntlm_header[2])) {
        $raw_server_challenge = base64_decode($ntlm_header[2]);
        break;
    }
}
$server_challenge = $challenge_message_decoder->decode($raw_server_challenge);

$authenticate_message = $authenticate_message_encoder->encode(
    $user_name,
    $target_name,
    $host_name,
    new Password($password),
    $server_challenge
);

// Send authenticate message
$request->setHeader('Authorization', sprintf('NTLM %s', base64_encode($authenticate_message)));
$client->send($request);
```


## TODO

- [x] LM hashing
- [x] NTv1 hashing
- [x] NTv2 hashing
- [x] NTLM negotiate message encoding
- [x] NTLM challenge message decoding
    - [x] Message structure and data validation
    - [x] Negotiate flag decoding
    - [x] Server challenge "nonce" handling
    - [x] TargetName parsing/handling
    - [x] \(Optional) TargetInfo parsing/handling
        - [ ] \(Optional) AV_PAIR decoding
    - [ ] \(Optional) Version parsing/handling (for debugging purposes only)
- [x] NTLM authenticate message encoding
    - [x] NTLM v1 response support
    - [x] NTLM v2 response support
    - [x] Extended session security (NTLM2 session key) support
    - [ ] \(Add-on) Encrypted session key exchange support
- [ ] Datagram ("connectionless") support
- [ ] Tests


## License

**PHP-NTLM** is licensed under the [Apache License, Version 2.0][license-file].

--------------------------------------------------------------------------------

Copyright 2019 Robin Powered, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.




[composer-website]: https://getcomposer.org/
[composer-documentation-autoloading]: https://getcomposer.org/doc/01-basic-usage.md#autoloading
[license-file]: LICENSE
