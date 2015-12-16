{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.Sodium.Stream.Salsa20
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
       , salsa20
       ) where

import qualified Crypto.Sodium.Stream.Internal as S
import           Foreign.C.Types               (CInt (..), CULLong (..))

foreign import ccall unsafe "crypto_stream_salsa20_keybytes"
    c_crypto_stream_salsa20_keybytes :: CInt

foreign import ccall unsafe "crypto_stream_salsa20_noncebytes"
    c_crypto_stream_salsa20_noncebytes :: CInt

foreign import ccall unsafe "crypto_stream_salsa20"
    c_crypto_stream_salsa20 :: S.StreamFn

foreign import ccall unsafe "crypto_stream_salsa20_xor"
    c_crypto_stream_salsa20_xor :: S.XorFn

data Salsa20
type Key = S.Key Salsa20
type Nonce = S.Nonce Salsa20

salsa20 :: S.StreamCipher Salsa20
salsa20 = S.mkStream c_crypto_stream_salsa20_keybytes c_crypto_stream_salsa20_noncebytes c_crypto_stream_salsa20 c_crypto_stream_salsa20_xor

S.StreamCipher {..} = salsa20
