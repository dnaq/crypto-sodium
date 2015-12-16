{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RecordWildCards            #-}
module Crypto.Sodium.Stream.Internal (StreamFn, XorFn, Key, Nonce, StreamCipher(..), mkStream) where

import           Crypto.Sodium.Internal   (mkHelper, mkSecureHelper)
import           Crypto.Sodium.Random     (randomSecret)
import           Crypto.Sodium.SecureMem  (SecureMem, withSecureMem)

import           Control.Monad            (void)
import           Data.ByteString          (ByteString)
import qualified Data.ByteString          as B
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Unsafe   as B
import           Data.Hashable            (Hashable)

import           Data.Word                (Word8)
import           Foreign.C.Types          (CChar, CInt (..), CULLong (..))
import           Foreign.Ptr              (Ptr)

type StreamFn = Ptr Word8 -> CULLong -> Ptr CChar -> Ptr Word8 -> IO CInt
type XorFn = Ptr Word8 -> Ptr CChar -> CULLong -> Ptr CChar -> Ptr Word8 -> IO CInt

newtype Key s = Key { _unKey :: SecureMem } deriving (Eq, Show)
newtype Nonce s = Nonce { _unNonce :: ByteString } deriving (Eq, Show, Ord, Hashable)

data StreamCipher s = StreamCipher
    { keyBytes   :: Int
    , nonceBytes :: Int
    , randomKey  :: IO (Key s)
    , mkKey      :: SecureMem -> Maybe (Key s)
    , unKey      :: Key s -> SecureMem
    , mkNonce    :: ByteString -> Maybe (Nonce s)
    , unNonce    :: Nonce s -> ByteString
    , stream     :: Key s -> Nonce s -> Int -> ByteString
    , streamXor  :: Key s -> Nonce s -> ByteString -> ByteString
    }


mkStream :: CInt -> CInt -> StreamFn -> XorFn -> StreamCipher s
mkStream c_keyBytes c_nonceBytes c_stream c_streamXor =
    StreamCipher {..}
    where
        keyBytes = fromIntegral c_keyBytes
        nonceBytes = fromIntegral c_nonceBytes
        randomKey = Key <$> randomSecret keyBytes
        mkKey = mkSecureHelper keyBytes Key
        unKey = _unKey
        mkNonce = mkHelper nonceBytes Nonce
        unNonce = _unNonce
        stream (Key k) (Nonce n) i =
            B.unsafeCreate i $ \pc ->
            B.unsafeUseAsCString n $ \pn ->
            withSecureMem k $
            void . c_stream pc (fromIntegral i) pn
        streamXor (Key k) (Nonce n) m =
            B.unsafeCreate mLen $ \pc ->
            B.unsafeUseAsCString m $ \pm ->
            B.unsafeUseAsCString n $ \pn ->
            withSecureMem k $
            void . c_streamXor pc pm (fromIntegral mLen) pn
            where mLen = B.length m
