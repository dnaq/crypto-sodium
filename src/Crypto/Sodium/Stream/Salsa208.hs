{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.Sodium.Stream.Salsa208
       ( keyBytes
       , nonceBytes
       , Key
       , mkKey
       , unKey
       , Nonce
       , mkNonce
       , unNonce
       , randomKey
       , stream
       , streamXor
       , salsa208
       ) where

import qualified Crypto.Sodium.Stream.Internal as S
import           Foreign.C.Types               (CInt (..), CULLong (..))

foreign import ccall unsafe "crypto_stream_salsa208_keybytes"
    c_crypto_stream_salsa208_keybytes :: CInt

foreign import ccall unsafe "crypto_stream_salsa208_noncebytes"
    c_crypto_stream_salsa208_noncebytes :: CInt

foreign import ccall unsafe "crypto_stream_salsa208"
    c_crypto_stream_salsa208 :: S.StreamFn

foreign import ccall unsafe "crypto_stream_salsa208_xor"
    c_crypto_stream_salsa208_xor :: S.XorFn

data Salsa208
type Key = S.Key Salsa208
type Nonce = S.Nonce Salsa208

salsa208 :: S.StreamCipher Salsa208
salsa208 = S.mkStream c_crypto_stream_salsa208_keybytes c_crypto_stream_salsa208_noncebytes c_crypto_stream_salsa208 c_crypto_stream_salsa208_xor

S.StreamCipher {..} = salsa208
