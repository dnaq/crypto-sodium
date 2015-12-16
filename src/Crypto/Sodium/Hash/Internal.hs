{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RecordWildCards            #-}
module Crypto.Sodium.Hash.Internal where

import           Crypto.Sodium.Internal   (constantTimeEq, mkHelper)

import           Control.Monad            (void)
import           Data.ByteString          (ByteString)
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Unsafe   as B
import           Data.Function            (on)
import           Data.Hashable            (Hashable)
import           Data.Word                (Word8)
import           Foreign.C.Types          (CChar, CInt (..), CULLong (..))
import           Foreign.Ptr              (Ptr)

type HashFn = Ptr Word8 -> Ptr CChar -> CULLong -> IO CInt

newtype Digest h = Digest { _unDigest :: ByteString } deriving (Show, Ord, Hashable)

instance Eq (Digest h) where
    (==) = constantTimeEq `on` _unDigest

data Hash h = Hash { digestBytes :: Int
                   , mkDigest    :: ByteString -> Maybe (Digest h)
                   , unDigest    :: Digest h -> ByteString
                   , hash        :: ByteString -> Digest h
                   }

mkHash :: CInt -> HashFn -> Hash h
mkHash c_digestBytes c_hash =
    Hash {..}
    where
        digestBytes = fromIntegral c_digestBytes
        mkDigest = mkHelper digestBytes Digest
        unDigest = _unDigest
        hash m =
            Digest $
            B.unsafeCreate digestBytes $ \pd ->
            B.unsafeUseAsCStringLen m $ \(pm, mLen) ->
            void $ c_hash pd pm (fromIntegral mLen)
