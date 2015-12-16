{- |
= Public-key authenticated encryption

== Security model
The 'seal' function is designed to meet the standard notions of privacy and
third-party unforgeability for a public-key authenticated-encryption scheme
using nonces. For formal definitions see, e.g., Jee Hea An, "Authenticated
encryption in the public-key setting: security notions and analyses,"
<http://eprint.iacr.org/2001/079>.

Distinct messages between the same {sender, receiver} set are required
to have distinct nonces. For example, the lexicographically smaller
public key can use nonce 1 for its first message to the other key, nonce
3 for its second message, nonce 5 for its third message, etc., while the
lexicographically larger public key uses nonce 2 for its first message
to the other key, nonce 4 for its second message, nonce 6 for its third
message, etc. Nonces are long enough that randomly generated nonces have
negligible risk of collision.

There is no harm in having the same nonce for different messages if the
{sender, receiver} sets are different. This is true even if the sets
overlap. For example, a sender can use the same nonce for two different
messages if the messages are sent to two different public keys.

The 'seal' function is not meant to provide non-repudiation. On the
contrary: the 'seal' function guarantees repudiability. A receiver
can freely modify a boxed message, and therefore cannot convince third
parties that this particular message came from the sender. The sender
and receiver are nevertheless protected against forgeries by other
parties. In the terminology of
<http://groups.google.com/group/sci.crypt/msg/ec5c18b23b11d82c>,
crypto_box uses "public-key authenticators" rather than "public-key
signatures."

Users who want public verifiability (or receiver-assisted public
verifiability) should instead use signatures (or signcryption).
Signature support is a high priority for NaCl; a signature API will be
described in subsequent NaCl documentation.

== Selected primitive
'seal' is `crypto_box_curve25519xsalsa20poly1305` , a particular
combination of Curve25519, Salsa20, and Poly1305 specified in
<http://nacl.cr.yp.to/valid.html Cryptography in NaCl>.

This function is conjectured to meet the standard notions of privacy and
third-party unforgeability.

== Example (simple interface)
>>> :set -XOverloadedStrings
>>> (ourPk, ourSk) <- randomKeypair
>>> (theirPk, theirSk) <- randomKeypair
>>> nonce <- randomNonce
>>> let plaintext = "some data" :: ByteString
>>> let ciphertext = seal theirPk ourSk nonce plaintext
>>> let (Just theirPlaintext) = open ourPk theirSk nonce ciphertext
>>> plaintext == theirPlaintext
True

== Example (precomputation interface)
>>> :set -XOverloadedStrings
>>> (ourPk, ourSk) <- randomKeypair
>>> (theirPk, theirSk) <- randomKeypair
>>> let ourPrecomputedKey = precompute theirPk ourSk
>>> nonce <- randomNonce
>>> let plaintext = "some data" :: ByteString
>>> let ciphertext = sealPrecomputed ourPrecomputedKey nonce plaintext
>>> -- theirPrecomputedKey will be identical to ourPrecomputedKey
>>> let theirPrecomputedKey = precompute ourPk theirSk
>>> let (Just theirPlaintext) = openPrecomputed theirPrecomputedKey nonce ciphertext
>>> plaintext == theirPlaintext
True
-}
module Crypto.Sodium.Box
       (-- * Constants
         publicKeyBytes -- | Number of bytes in a 'PublicKey'.
       , secretKeyBytes -- | Number of bytes in a 'SecretKey'.
       , nonceBytes -- | Number of bytes in a 'Nonce'.
       , precomputedKeyBytes -- | Number of bytes in a 'PrecomputedKey'.
       , seedBytes -- | Number of bytes in a 'Seed'.

         -- * Types
       , PublicKey -- | 'PublicKey' for asymmetric authenticated encryption.
       , mkPublicKey -- | Smart constructor for 'PublicKey'. Verifies
                     -- that the length of the parameter is 'publicKeyBytes'.
       , unPublicKey -- | Returns the contents of a 'PublicKey'.
       , SecretKey -- | 'SecretKey' for asymmetric authenticated encryption.
       , mkSecretKey -- | Smart constructor for 'SecretKey'. Verifies that the
                     -- length of the parameter is 'secretKeyBytes'.
       , unSecretKey -- | Returns the contents of a 'SecretKey'.
       , Nonce -- | 'Nonce' for asymmetric authenticated encryption.
       , mkNonce -- | Smart constructor for 'Nonce'. Verifies that the length of
                 -- the parameter is 'nonceBytes'.
       , unNonce -- | Returns the contents of a 'Nonce'.
       , PrecomputedKey -- | 'PrecomputedKey' for asymmetric authenticated
                        -- encryption.
       , mkPrecomputedKey -- | Smart constructor for 'PrecomputedKey'. Verifies
                          -- that the length of the parameter is
                          -- 'precomputedKeyBytes'.
       , unPrecomputedKey -- | Returns the contents of a 'PrecomputedKey'.
       , Seed -- | 'Seed' for deterministic key generation.
       , mkSeed -- | Smart constructor for 'Seed'. Verifies that the length of
                -- the parameter is 'seedBytes'.
       , unSeed -- | Returns the contents of a 'Seed'.

         -- * Key Generation
       , randomKeypair -- | Randomly generates a 'SecretKey' and the corresponding 'PublicKey'.
       , keypairFromSeed -- | Computes a 'SecretKey' and the corresponding
                         -- 'PublicKey' from a 'Seed'.
       , randomSeed -- | Randomly generates a 'Seed'.

         -- * Nonce Generation
       , randomNonce -- | Randomly generates a 'Nonce'.

         -- * Sealing/Opening
       , seal -- | Encrypts and authenticates a message using the senders
              -- 'SecretKey', the receivers 'PublicKey', and a 'Nonce'.
              -- It returns a ciphertext.
       , open -- | Verifies and decrypts a ciphertext using the receivers
              -- 'SecretKey', the senders 'PublicKey', and a 'Nonce'.
              -- It returns a plaintext. If the ciphertext fails verification,
              -- 'open' returns 'Nothing'.

         -- * Precomputation Interface
         -- | Applications that send several messages to the same receiver can
         -- gain speed by splitting 'seal' into two steps, 'precompute'
         -- and 'sealPrecomputed'. Similarly, applications that receive several
         -- messages from the same sender can gain speed by splitting 'open'
         -- into two steps, 'precompute' and 'openPrecomputed'.
       , precompute -- | Computes an intermediate key that can be used by
                    -- 'sealPrecomputed' and 'openPrecomputed'.
       , sealPrecomputed -- | Encrypts and authenticates a message using a
                         -- 'PrecomputedKey'. Returns a ciphertext.
       , openPrecomputed -- | Verifies and decrypts a ciphertext using a
                         -- 'PrecomputedKey'. Returns a plaintext.
                         -- If the ciphertext fails verification
                         -- 'openPrecomputed' returns 'Nothing'.
       ) where

import           Crypto.Sodium.Box.Curve25519Xsalsa20Poly1305
