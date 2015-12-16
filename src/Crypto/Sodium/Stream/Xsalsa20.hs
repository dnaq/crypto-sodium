{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.Sodium.Stream.Xsalsa20
       ( keyBytes
       , nonceBytes
       , Key
       , mkKey
       , unKey
       , Nonce
       , mkNonce
       , unNonce
       , randomKey
       , randomNonce
       , stream
       , streamXor
       , xsalsa20
       ) where

import           Crypto.Sodium.Random          (randomBytes)
import qualified Crypto.Sodium.Stream.Internal as S
import           Data.Maybe                    (fromJust)
import           Foreign.C.Types               (CInt (..), CULLong (..))

foreign import ccall unsafe "crypto_stream_xsalsa20_keybytes"
    c_crypto_stream_xsalsa20_keybytes :: CInt

foreign import ccall unsafe "crypto_stream_xsalsa20_noncebytes"
    c_crypto_stream_xsalsa20_noncebytes :: CInt

foreign import ccall unsafe "crypto_stream_xsalsa20"
    c_crypto_stream_xsalsa20 :: S.StreamFn

foreign import ccall unsafe "crypto_stream_xsalsa20_xor"
    c_crypto_stream_xsalsa20_xor :: S.XorFn

data Xsalsa20
type Key = S.Key Xsalsa20
type Nonce = S.Nonce Xsalsa20

xsalsa20 :: S.StreamCipher Xsalsa20
xsalsa20 = S.mkStream c_crypto_stream_xsalsa20_keybytes c_crypto_stream_xsalsa20_noncebytes c_crypto_stream_xsalsa20 c_crypto_stream_xsalsa20_xor

S.StreamCipher {..} = xsalsa20

randomNonce :: IO Nonce
randomNonce = fromJust . mkNonce <$> randomBytes nonceBytes
