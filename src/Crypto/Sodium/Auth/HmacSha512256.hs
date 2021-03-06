{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# LANGUAGE RecordWildCards #-}
{- |
See the documentation in "Crypto.Sodium.Auth".
-}
module Crypto.Sodium.Auth.HmacSha512256
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
       , hmacSha512256
       ) where

import qualified Crypto.Sodium.Auth.Internal as A
import           Foreign.C.Types             (CInt (..), CULLong (..))

foreign import ccall unsafe "crypto_auth_hmacsha512256_bytes"
    c_crypto_auth_hmacsha512256_bytes :: CInt

foreign import ccall unsafe "crypto_auth_hmacsha512256_keybytes"
    c_crypto_auth_hmacsha512256_keybytes :: CInt

foreign import ccall unsafe "crypto_auth_hmacsha512256"
    c_crypto_auth_hmacsha512256 :: A.AuthFn

foreign import ccall unsafe "crypto_auth_hmacsha512256_verify"
    c_crypto_auth_hmacsha512256_verify :: A.VerifyFn

data HmacSha512256

type Key = A.Key HmacSha512256
type Tag = A.Tag HmacSha512256

hmacSha512256 :: A.Auth HmacSha512256
hmacSha512256 = A.mkAuth c_crypto_auth_hmacsha512256_keybytes
                         c_crypto_auth_hmacsha512256_bytes
                         c_crypto_auth_hmacsha512256
                         c_crypto_auth_hmacsha512256_verify

A.Auth {..} = hmacSha512256
