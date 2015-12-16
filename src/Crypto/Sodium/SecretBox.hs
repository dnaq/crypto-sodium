{- |
= Secret-key authenticated encryption

== Security model
The 'seal' function is designed to meet the standard notions of privacy and
authenticity for a secret-key authenticated-encryption scheme using nonces. For
formal definitions see, e.g., Bellare and Namprempre, "Authenticated
encryption: relations among notions and analysis of the generic composition
paradigm," Lecture Notes in Computer Science 1976 (2000), 531–545,
<http://www-cse.ucsd.edu/~mihir/papers/oem.html>.

Note that the length is not hidden. Note also that it is the caller's
responsibility to ensure the uniqueness of nonces—for example, by using
nonce 1 for the first message, nonce 2 for the second message, etc.
Nonces are long enough that randomly generated nonces have negligible
risk of collision.

== Selected primitive
'seal' is `crypto_secretbox_xsalsa20poly1305`, a particular
combination of Salsa20 and Poly1305 specified in
<http://nacl.cr.yp.to/valid.html Cryptography in NaCl>.

This function is conjectured to meet the standard notions of privacy and
authenticity.

== Example
>>> :set -XOverloadedStrings
>>> key <- randomKey
>>> nonce <- randomNonce
>>> let plaintext = "some data" :: ByteString
>>> let ciphertext = seal key nonce plaintext
>>> let (Just theirPlaintext) = open key nonce ciphertext
>>> plaintext == theirPlaintext
True
-}
module Crypto.Sodium.SecretBox
       ( -- * Constants
         keyBytes -- | Number of bytes in a 'Key'
       , nonceBytes -- | Number of bytes in a 'Nonce'

         -- * Types
       , Key -- | 'Key' for authenticated encryption
       , mkKey -- | Smart constructor for 'Key'
               --   returns 'Just' a 'Key' if the parameter is of length 'keyBytes'
       , unKey
       , Nonce -- | 'Nonce' for authenticated encryption
       , mkNonce -- | Smart constructor for 'Nonce'
                  --  returns 'Just' a 'Nonce' if the parameter is of length 'nonceBytes'
       , unNonce

         -- * Key Generation
       , randomKey -- | Randomly generates a 'Key'

         -- * Nonce Generation
       , randomNonce -- | Randomly generates a 'Nonce'

         -- * Sealing/Opening
       , seal -- | Encrypts and authenticates a message using a 'Key' and a 'Nonce'.
              --   It returns a ciphertext.
       , open -- | Verifies and decrypts a ciphertext using a 'Key' and a 'Nonce'.
              --   It returns a plaintext. If the ciphertext fails verification, 'open'
              --   returns 'Nothing'
       ) where

import           Crypto.Sodium.SecretBox.Xsalsa20Poly1305
