# PHP NTLM

PHP-NTLM is a library that handles the encoding and decoding of messages used in the challenge-and-response flow of the
NTLM authentication protocol, while also providing separate injectable credential hashing mechanisms to allow for a more
secure version of a credential for storage (rather than storing passwords in "plain-text").


## Features

- NTLM client message encoding and decoding
- Multiple text-encoding native-extensions supported
- LM, NTv1, and NTv2 hashing algorithms supported


## Requirements

- 64-bit PHP runtime (NTLM negotiation bit flags extend beyond the 32-bit integer size)
- PHP `>=5.3.0`


## Installation

1. [Get Composer][composer-website]
2. Add `robinpowered/php-ntlm` to your Composer required dependencies: `composer require robinpowered/php-ntlm`
3. Include the [Composer autoloader][composer-documentation-autoloading]


## TODO

- [x] LM hashing
- [x] NTv1 hashing
- [x] NTv2 hashing
- [x] NTLM negotiate message encoding
- [x] NTLM challenge message decoding
    - [x] Message structure and data validation
    - [x] Negotiate flag decoding
    - [x] Server challenge "nonce" handling
    - [ ] \(Optional) TargetName parsing/handling
    - [ ] \(Optional) TargetInfo parsing/handling
    - [ ] \(Optional) Version parsing/handling (for debugging purposes only)
- [ ] NTLM authenticate message encoding
    - [ ] NTLM v1 response support
    - [ ] NTLM v2 response support
    - [ ] Encrypted session key exchange support
- [ ] Tests... ugh.


## License

**PHP-NTLM** is licensed under the [Apache License, Version 2.0][license-file].

--------------------------------------------------------------------------------

Copyright 2015 Robin Powered, Inc.

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
