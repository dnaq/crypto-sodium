{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# LANGUAGE RecordWildCards #-}
{- |
See the documentation in "Crypto.Sodium.OneTimeAuth".
-}
module Crypto.Sodium.OnetimeAuth.Poly1305
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
       , poly1305
       ) where

import qualified Crypto.Sodium.Auth.Internal as A
import           Foreign.C.Types             (CInt (..), CULLong (..))

foreign import ccall unsafe "crypto_onetimeauth_poly1305_bytes"
    c_crypto_onetimeauth_poly1305_bytes :: CInt

foreign import ccall unsafe "crypto_onetimeauth_poly1305_keybytes"
    c_crypto_onetimeauth_poly1305_keybytes :: CInt

foreign import ccall unsafe "crypto_onetimeauth_poly1305"
    c_crypto_onetimeauth_poly1305 :: A.AuthFn

foreign import ccall unsafe "crypto_onetimeauth_poly1305_verify"
    c_crypto_onetimeauth_poly1305_verify :: A.VerifyFn

data Poly1305

type Key = A.Key Poly1305
type Tag = A.Tag Poly1305

poly1305 :: A.Auth Poly1305
poly1305 = A.mkAuth c_crypto_onetimeauth_poly1305_keybytes
                    c_crypto_onetimeauth_poly1305_bytes
                    c_crypto_onetimeauth_poly1305
                    c_crypto_onetimeauth_poly1305_verify

A.Auth {..} = poly1305
