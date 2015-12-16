{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.Sodium.Stream.Aes128Ctr
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
       , aes128Ctr
       ) where

import qualified Crypto.Sodium.Stream.Internal as S
import           Foreign.C.Types               (CInt (..), CULLong (..))

foreign import ccall unsafe "crypto_stream_aes128ctr_keybytes"
    c_crypto_stream_aes128ctr_keybytes :: CInt

foreign import ccall unsafe "crypto_stream_aes128ctr_noncebytes"
    c_crypto_stream_aes128ctr_noncebytes :: CInt

foreign import ccall unsafe "crypto_stream_aes128ctr"
    c_crypto_stream_aes128ctr :: S.StreamFn

foreign import ccall unsafe "crypto_stream_aes128ctr_xor"
    c_crypto_stream_aes128ctr_xor :: S.XorFn

data Aes128Ctr
type Key = S.Key Aes128Ctr
type Nonce = S.Nonce Aes128Ctr

aes128Ctr :: S.StreamCipher Aes128Ctr
aes128Ctr = S.mkStream c_crypto_stream_aes128ctr_keybytes c_crypto_stream_aes128ctr_noncebytes c_crypto_stream_aes128ctr c_crypto_stream_aes128ctr_xor

S.StreamCipher {..} = aes128Ctr
