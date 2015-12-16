{-# LANGUAGE RecordWildCards #-}
module Crypto.Sodium.Auth.Internal where

import           Crypto.Sodium.Internal   (constantTimeEq, mkHelper,
                                           mkSecureHelper)
import           Crypto.Sodium.Random     (randomSecret)
import           Crypto.Sodium.SecureMem  (SecureMem, withSecureMem)

import           Control.Monad            (void)
import           Data.ByteString          (ByteString)
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Unsafe   as B
import           Data.Function            (on)
import           Data.Word                (Word8)
import           Foreign.C.Types          (CChar, CInt (..), CULLong (..))
import           Foreign.Ptr              (Ptr)
import           System.IO.Unsafe         (unsafeDupablePerformIO)

type AuthFn = Ptr Word8 -> Ptr CChar -> CULLong -> Ptr Word8 -> IO CInt
type VerifyFn = Ptr CChar -> Ptr CChar -> CULLong -> Ptr Word8 -> IO CInt

newtype Key a = Key { _unKey :: SecureMem } deriving (Eq, Show)
newtype Tag a = Tag { _unTag :: ByteString } deriving (Show, Ord)

instance Eq (Tag a) where
    (==) = constantTimeEq `on` _unTag

data Auth a = Auth { keyBytes     :: Int
                   , tagBytes     :: Int
                   , mkKey        :: SecureMem -> Maybe (Key a)
                   , unKey        :: Key a -> SecureMem
                   , mkTag        :: ByteString -> Maybe (Tag a)
                   , unTag        :: Tag a -> ByteString
                   , randomKey    :: IO (Key a)
                   , authenticate :: Key a -> ByteString -> Tag a
                   , verify       :: Key a -> ByteString -> Tag a -> Bool
                   }

mkAuth :: CInt -> CInt -> AuthFn -> VerifyFn -> Auth a
mkAuth c_keyBytes c_tagBytes c_authenticate c_verify = Auth {..}
    where
        keyBytes = fromIntegral c_keyBytes
        tagBytes = fromIntegral c_tagBytes
        randomKey = Key <$> randomSecret keyBytes
        mkKey = mkSecureHelper keyBytes Key
        unKey = _unKey
        mkTag = mkHelper tagBytes Tag
        unTag = _unTag
        authenticate (Key k) m =
            Tag $
            B.unsafeCreate tagBytes $ \pt ->
            B.unsafeUseAsCStringLen m $ \(pm, mLen) ->
            withSecureMem k $
            void . c_authenticate pt pm (fromIntegral mLen)
        verify (Key k) m (Tag t) =
            (==0) $ unsafeDupablePerformIO $
            B.unsafeUseAsCString t $ \pt ->
            B.unsafeUseAsCStringLen m $ \(pm, mLen) ->
            withSecureMem k $
            c_verify pt pm (fromIntegral mLen)
