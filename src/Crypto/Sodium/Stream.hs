{- |
= Secret-key encryption

== Security Model
The 'stream' function, viewed as a function of the nonce for a
uniform random key, is designed to meet the standard notion of
unpredictability (PRF). For a formal definition see, e.g., Section 2.3
of Bellare, Kilian, and Rogaway, "The security of the cipher block
chaining message authentication code," Journal of Computer and System
Sciences 61 (2000), 362–399;
<http://www-cse.ucsd.edu/~mihir/papers/cbc.html>.

This means that an attacker cannot distinguish this function from a
uniform random function. Consequently, if a series of messages is
encrypted by 'streamXor' with a different nonce for each message,
the ciphertexts are indistinguishable from uniform random strings of the
same length.

Note that the length is not hidden. Note also that it is the caller's
responsibility to ensure the uniqueness of nonces—for example, by using
nonce 1 for the first message, nonce 2 for the second message, etc.
Nonces are long enough that randomly generated nonces have negligible
risk of collision.

NaCl does not make any promises regarding the resistance of 'stream' to
"related-key attacks." It is the caller's responsibility to use proper
key-derivation functions.

== Selected primitive
'stream' is 'crypto_stream_xsalsa20', a particular cipher specified in
<http://nacl.cr.yp.to/valid.html, Cryptography in NaCl>, Section 7.
This cipher is conjectured to meet the standard notion of
unpredictability.

== Alternate primitives
NaCl supports the following secret-key encryption functions:

> ------------------------------------------------------------
> |crypto_stream           |primitive   |KEYBYTES |NONCEBYTES|
> |------------------------|------------|---------|----------|
> |crypto_stream_aes128ctr |AES-128-CTR |16       |16        |
> |crypto_stream_chacha20  |Chacha20/20 |32       |8         |
> |crypto_stream_salsa208  |Salsa20/8   |32       |8         |
> |crypto_stream_salsa2012 |Salsa20/12  |32       |8         |
> |crypto_stream_salsa20   |Salsa20/20  |32       |8         |
> |crypto_stream_xsalsa20  |XSalsa20/20 |32       |24        |
> ------------------------------------------------------------

Beware that several of these primitives have 8-byte nonces. For those
primitives it is no longer true that randomly generated nonces have negligible
risk of collision. Callers who are unable to count 1, 2, 3..., and who insist
on using these primitives, are advised to use a randomly derived key for each
message. For this reason the primitives with 8-byte nonces do not export a
'randomNonce' function.

== Example (keystream generation)
>>> key <- randomKey
>>> nonce <- randomNonce
>>> let keystream = stream key nonce 128 -- generate 128 bytes of keystream

== Example (encryption)
>>> :set -XOverloadedStrings
>>> key <- randomKey
>>> nonce <- randomNonce
>>> let plaintext = "some data"
>>> let ciphertext = streamXor key nonce plaintext
>>> let theirPlaintext = streamXor key nonce ciphertext
>>> plaintext == theirPlaintext
True
-}
module Crypto.Sodium.Stream
       ( -- * Constants
         keyBytes -- | Number of bytes in a 'Key'.
       , nonceBytes -- | Number of bytes in a 'Nonce'.

         -- * Types
       , Key -- | 'Key' for encryption.
       , mkKey -- | Smart constructor for 'Key'. Verifies that the length
               -- of the parameter is 'keyBytes'.
       , unKey -- | Returns the contents of a 'Key'.
       , Nonce -- | 'Nonce' for encryption.
       , mkNonce -- | Smart constructor for 'Nonce'. Verifies that the length
                 -- of the parameter is 'nonceBytes'.
       , unNonce -- | Returns the contents of a 'Nonce'.

         -- * Key Generation
       , randomKey -- | Randomly generates a 'Key'.

         -- * Nonce Generation
       , randomNonce -- | Randomly generates a 'Nonce'.

         -- * Encryption/Decryption
       , stream -- | Generates a keystream.
       , streamXor -- | Encrypts/decrypts a message.
       ) where

import           Crypto.Sodium.Stream.Xsalsa20
