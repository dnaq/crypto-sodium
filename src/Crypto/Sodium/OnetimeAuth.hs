{-|
= Secret-key One-time authentication

== Security model
The 'authenticate' function, viewed as a function
of the message for a uniform random key, is designed to meet the
standard notion of unforgeability after a single message. After the
sender authenticates one message, an attacker cannot find authenticators
for any other messages.

The sender must not use 'authenticate' to authenticate more than one message
under the same key. Authenticators for two messages under the same key should
be expected to reveal enough information to allow forgeries of authenticators
on other messages.

== Selected primitive
'authenticate' is 'crypto_onetimeauth_poly1305', an authenticator specified
in <http://nacl.cr.yp.to/valid.html, Cryptography in NaCl>, Section 9. This
authenticator is proven to meet the standard notion of unforgeability after a
single message.

== Example
>>> :set -XOverloadedStrings
>>> k <- randomKey
>>> let msg = "some data"
>>> let tag = authenticate k msg
>>> verify k msg tag
True
>>> k <- randomKey
>>> verify k msg tag
False
-}
module Crypto.Sodium.OnetimeAuth
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
                -- of a message under a secret 'Key'. Otherwise it returns
                -- 'False'.
       ) where

import           Crypto.Sodium.OnetimeAuth.Poly1305
