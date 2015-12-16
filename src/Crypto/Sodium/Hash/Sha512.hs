{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# LANGUAGE RecordWildCards #-}
{- |
See the documentation in "Crypto.Sodium.Hash".
-}
module Crypto.Sodium.Hash.Sha512
       ( -- * Constants
         digestBytes -- | Number of bytes in a 'Digest'.

         -- * Types
       , Digest -- | Digest structure.
       , unDigest -- | Returns the contents of a 'Digest'.
       , mkDigest -- | Smart constructor for 'Digest'. Verifies that the length
                  -- of the parameter is 'digestBytes'.

         -- * Hashing
       , hash -- | Hashes a message.
       , sha512
       ) where

import qualified Crypto.Sodium.Hash.Internal as H

import           Foreign.C.Types             (CInt (..), CULLong (..))

foreign import ccall unsafe "crypto_hash_sha512_bytes"
    c_crypto_hash_sha512_bytes :: CInt

foreign import ccall unsafe "crypto_hash_sha512"
    c_crypto_hash_sha512 :: H.HashFn

data Sha512
type Digest = H.Digest Sha512

sha512 :: H.Hash Sha512
sha512 = H.mkHash c_crypto_hash_sha512_bytes c_crypto_hash_sha512

H.Hash {..} = sha512
