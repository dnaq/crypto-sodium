{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.Sodium.Stream.Chacha20
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
       , chacha20
       ) where

import qualified Crypto.Sodium.Stream.Internal as S
import           Foreign.C.Types               (CInt (..), CULLong (..))

foreign import ccall unsafe "crypto_stream_chacha20_keybytes"
    c_crypto_stream_chacha20_keybytes :: CInt

foreign import ccall unsafe "crypto_stream_chacha20_noncebytes"
    c_crypto_stream_chacha20_noncebytes :: CInt

foreign import ccall unsafe "crypto_stream_chacha20"
    c_crypto_stream_chacha20 :: S.StreamFn

foreign import ccall unsafe "crypto_stream_chacha20_xor"
    c_crypto_stream_chacha20_xor :: S.XorFn

data Chacha20
type Key = S.Key Chacha20
type Nonce = S.Nonce Chacha20

chacha20 :: S.StreamCipher Chacha20
chacha20 = S.mkStream c_crypto_stream_chacha20_keybytes c_crypto_stream_chacha20_noncebytes c_crypto_stream_chacha20 c_crypto_stream_chacha20_xor

S.StreamCipher {..} = chacha20
