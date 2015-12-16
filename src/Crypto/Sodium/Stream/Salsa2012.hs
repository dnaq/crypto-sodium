{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.Sodium.Stream.Salsa2012
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
       , salsa2012
       ) where

import qualified Crypto.Sodium.Stream.Internal as S
import           Foreign.C.Types               (CInt (..), CULLong (..))

foreign import ccall unsafe "crypto_stream_salsa2012_keybytes"
    c_crypto_stream_salsa2012_keybytes :: CInt

foreign import ccall unsafe "crypto_stream_salsa2012_noncebytes"
    c_crypto_stream_salsa2012_noncebytes :: CInt

foreign import ccall unsafe "crypto_stream_salsa2012"
    c_crypto_stream_salsa2012 :: S.StreamFn

foreign import ccall unsafe "crypto_stream_salsa2012_xor"
    c_crypto_stream_salsa2012_xor :: S.XorFn

data Salsa2012
type Key = S.Key Salsa2012
type Nonce = S.Nonce Salsa2012

salsa2012 :: S.StreamCipher Salsa2012
salsa2012 = S.mkStream c_crypto_stream_salsa2012_keybytes c_crypto_stream_salsa2012_noncebytes c_crypto_stream_salsa2012 c_crypto_stream_salsa2012_xor

S.StreamCipher {..} = salsa2012
