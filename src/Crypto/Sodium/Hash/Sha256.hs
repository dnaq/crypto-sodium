{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# LANGUAGE RecordWildCards #-}
{- |
See the documentation in "Crypto.Sodium.Hash".
-}
module Crypto.Sodium.Hash.Sha256
       ( -- * Constants
         digestBytes -- | Number of bytes in a 'Digest'.

         -- * Types
       , Digest -- | Digest structure.
       , unDigest -- | Returns the contents of a 'Digest'.
       , mkDigest -- | Smart constructor for 'Digest'. Verifies that the length
                  -- of the parameter is 'digestBytes'.

         -- * Hashing
       , hash -- | Hashes a message.
       , sha256
       ) where

import qualified Crypto.Sodium.Hash.Internal as H

import           Foreign.C.Types             (CInt (..), CULLong (..))

foreign import ccall unsafe "crypto_hash_sha256_bytes"
    c_crypto_hash_sha256_bytes :: CInt

foreign import ccall unsafe "crypto_hash_sha256"
    c_crypto_hash_sha256 :: H.HashFn

data Sha256
type Digest = H.Digest Sha256

sha256 :: H.Hash Sha256
sha256 = H.mkHash c_crypto_hash_sha256_bytes c_crypto_hash_sha256

H.Hash {..} = sha256
