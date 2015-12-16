{- |
= Public-key signatures

== Security model
The 'sign' function is designed to meet the standard
notion of unforgeability for a public-key signature scheme under
chosen-message attacks.

== Selected primitive
'sign' is 'ed25519', a signature scheme specified in
<http://ed25519.cr.yp.to/, Ed25519>. This function is conjectured to
meet the standard notion of unforgeability for a public-key signature
scheme under chosen-message attacks.

== Alternate primitives

> --------------------------------------------------------------------------------
> |crypto_sign                         | PUBLICKEYBYTES | SECRETKEYBYTES | BYTES |
> |------------------------------------|----------------|----------------|-------|
> |crypto_sign_ed25519                 | 32             | 64             | 64    |
> |crypto_sign_edwards25519sha512batch | 32             | 64             | 64    |
> --------------------------------------------------------------------------------

crypto_sign_edwards25519sha512batch is a prototype. It has been replaced with
Ed25519 and is only kept here for compatibility reasons.

== Example
>>> :set -XOverloadedStrings
>>> (pk, sk) <- randomKeypair
>>> let sm = sign sk "some data"
>>> verify pk sm
Just "some data"
>>> (pk, _) <- randomKeypair
>>> verify pk sm
Nothing

== Example (detached signatures)
>>> :set -XOverloadedStrings
>>> (pk, sk) <- randomKeypair
>>> let msg = "some data"
>>> let sig = signDetached sk msg
>>> verifyDetached pk msg sig
True
>>> (pk, _) <- randomKeypair
>>> verifyDetached pk msg sig
False
-}
module Crypto.Sodium.Sign
       ( -- * Constants
         publicKeyBytes -- | Number of bytes in a 'PublicKey'.
       , secretKeyBytes -- | Number of bytes in a 'SecretKey'.
       , seedBytes -- | Number of bytes in a 'Seed'.
       , signatureBytes -- | Number of bytes in a 'Signature'.

         -- * Types
       , PublicKey -- | 'PublicKey' for asymmetric signing.
       , mkPublicKey -- | Smart constructor for 'PublicKey'. Verifies that
                     -- the length of the parameter is 'publicKeyBytes'.
       , unPublicKey -- | Returns the contents of a 'PublicKey'.
       , SecretKey -- | 'SecretKey' for asymmetric signing.
       , mkSecretKey -- | Smart constructor for 'SecretKey'. Verifies that
                     -- the length of the parameter is 'secretKeyBytes'.
       , unSecretKey -- | Returns the contents of a 'SecretKey'.
       , Seed -- | 'Seed' for deterministic key generation.
       , mkSeed -- | Smart constructor for 'Seed'. Verifies that the length of
                -- the parameter is 'seedBytes'.
       , unSeed -- | Returns the contents of a 'Seed'.
       , Signature -- | A 'Signature' of a message.
       , mkSignature -- | Smart constructor for 'Signature'. Verifies that
                     -- the length of the parameter is 'signatureBytes'.
       , unSignature -- | Returns the contents of a 'Signature'.

         -- * Key Generation
       , randomKeypair -- | Randomly generates a 'SecretKey' and the corresponding
                       -- 'PublicKey'.
       , keypairFromSeed -- | Computes a 'SecretKey' and the corresponding
                         -- 'PublicKey' from a 'Seed'.
       , randomSeed -- | Randomly generates a 'Seed'.

         -- * Signing/Verifying
       , sign -- | Signs a message using a 'SecretKey'. Returns the signed message.
       , verify -- | Verifies that a message has been signed by the 'SecretKey'
                -- corresponding to the 'PublicKey' given as a parameter.
                -- If verification succeeds it returns 'Just' the
                -- contents of the message, otherwise it returns 'Nothing'.
       , signDetached -- | Signs a message using a 'SecretKey'. Returns a detached
                      -- 'Signature'.
       , verifyDetached -- | Verifies that a message with a detached 'Signature' has
                        -- been signed by the 'SecretKey' corresponding to the
                        -- 'PublicKey' given as a parameter.

         -- * Key Conversion
       , skToSeed -- | Converts a 'SecretKey' to a 'Seed'.
       , skToPk -- | Computes the corresponding 'PublicKey' from a 'SecretKey'.
       , pkToCurve25519 -- | Converts a 'PublicKey' to a 'Curve25519.PublicKey'
                        -- for use in asymmetric authenticated encryption.
                        --
                        -- WARNING: This function should only be used if
                        -- you are absolutely sure of what you're doing.
                        -- Using the same key for different purposes will
                        -- open up for cross protocol attacks unless you're
                        -- extremely careful.
       , skToCurve25519 -- | Converts a 'SecretKey' to a 'Curve25519.SecretKey'
                        -- for use in asymmetric authenticated encryption.
                        --
                        -- WARNING: This function should only be used if
                        -- you are absolutely sure of what you're doing.
                        -- Using the same key for different purposes will
                        -- open up for cross protocol attacks unless you're
                        -- extremely careful.
       ) where

import           Crypto.Sodium.Sign.Ed25519
