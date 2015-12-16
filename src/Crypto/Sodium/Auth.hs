{-|
= Secret-key authentication

== Security model
The 'authenticate' function, viewed as a function of the
message for a uniform random key, is designed to meet the standard
notion of unforgeability. This means that an attacker cannot find
authenticators for any messages not authenticated by the sender, even if
the attacker has adaptively influenced the messages authenticated by the
sender. For a formal definition see, e.g., Section 2.4 of Bellare,
Kilian, and Rogaway, "The security of the cipher block chaining message
authentication code," Journal of Computer and System Sciences 61 (2000),
362–399; http://www-cse.ucsd.edu/~mihir/papers/cbc.html.

NaCl does not make any promises regarding "strong" unforgeability;
perhaps one valid authenticator can be converted into another valid
authenticator for the same message. NaCl also does not make any promises
regarding "truncated unforgeability."

== Selected primitive
'authenticate' is currently an implementation of
'HMAC-SHA-512-256', i.e., the first 256 bits of 'HMAC-SHA-512'.
'HMAC-SHA-512-256' is conjectured to meet the standard notion of
unforgeability.

== Alternate primitives
NaCl supports the following secret-key authentication functions:

> ------------------------------------------------------------
> |crypto_auth              |primitive        |BYTES|KEYBYTES|
> |-------------------------|-----------------|-----|--------|
> |crypto_auth_hmacsha256   |HMAC_SHA-256     |32   |32      |
> |crypto_auth_hmacsha512256|HMAC_SHA-512-256 |32   |32      |
> |crypto_auth_hmacsha512   |HMAC_SHA-512     |64   |32      |
> ------------------------------------------------------------

== Example
>>> :set -XOverloadedStrings
>>> key <- randomKey
>>> let msg = "some data"
>>> let tag = authenticate k msg
>>> verify key msg tag
True
>>> key <- randomKey
>>> verify key msg tag
False
-}
module Crypto.Sodium.Auth
       ( -- * Constants
         keyBytes -- | Number of bytes in an authentication 'Key'.
       , tagBytes -- | Number of bytes in an authentication 'Tag'.

         -- * Types
       , Key -- | Authentication 'Key'
       , mkKey -- | Smart constructor for 'Key'. Verifies that the length of the
               -- parameter is 'keyBytes'.
       , unKey -- | Returns the contents of a 'Key'
       , Tag -- | Authentication 'Tag'
       , mkTag -- | Smart constructor for 'Tag'. Verifies thta the length of the
               -- parameter is 'tagBytes'
       , unTag -- | Returns the contents of a 'Tag'

         -- * Key Generation
       , randomKey -- | Randomly generates a 'Key' for authentication.

         -- * Authentication/Verification
       , authenticate -- | Authenticates a message using a secret 'Key'
       , verify -- | Returns 'True' if 'Tag' is a correct authenticator
                -- of a message under a secret 'Key'. Otherwise it returns 'False'.
       ) where

import           Crypto.Sodium.Auth.HmacSha512256
