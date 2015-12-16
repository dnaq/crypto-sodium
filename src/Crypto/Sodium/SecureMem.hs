module Crypto.Sodium.SecureMem (SecureMem, create, create', fromByteString, toByteString, length, withSecureMem) where

import           Prelude                  hiding (length)

import           Data.ByteString          (ByteString)
import qualified Data.ByteString          as B
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Unsafe   as B
import           Data.Word                (Word8)
import           Foreign.C.Types          (CInt (..), CSize (..))
import qualified Foreign.Concurrent       as FC
import           Foreign.ForeignPtr       (ForeignPtr, mallocForeignPtrBytes,
                                           withForeignPtr)
import           Foreign.Ptr              (Ptr, castPtr)
import           System.IO.Unsafe         (unsafeDupablePerformIO)

foreign import ccall unsafe "sodium.h sodium_memzero"
  c_sodium_memzero :: Ptr Word8 -> CSize -> IO ()

foreign import ccall unsafe "sodium.h sodium_memcmp"
  c_sodium_memcmp :: Ptr Word8 -> Ptr Word8 -> CSize -> IO CInt

data SecureMem = SecureMem !(ForeignPtr Word8) !Int

instance Show SecureMem where
  show _ = "SecureMem <secret>"

instance Eq SecureMem where
  sm1 == sm2 = unsafeDupablePerformIO $
               withSecureMemSz sm1 $ \i1 p1 ->
               withSecureMemSz sm2 $ \i2 p2 ->
               if i1 == i2
               then (==0) <$> c_sodium_memcmp p1 p2 (fromIntegral i1)
               else return False

create :: Int -> (Ptr Word8 -> IO ()) -> IO SecureMem
create i f = fst <$> create' i f

create' :: Int -> (Ptr Word8 -> IO a) -> IO (SecureMem, a)
create' i f = do
  fp <- mallocForeignPtrBytes i
  FC.addForeignPtrFinalizer fp $
    withForeignPtr fp $ \p -> c_sodium_memzero p (fromIntegral i)
  r <- withForeignPtr fp f
  return (SecureMem fp i, r)

withSecureMem :: SecureMem -> (Ptr Word8 -> IO a) -> IO a
withSecureMem (SecureMem sm _) = withForeignPtr sm

withSecureMemSz :: SecureMem -> (Int -> Ptr Word8 -> IO a) -> IO a
withSecureMemSz (SecureMem sm i) f = withForeignPtr sm (f i)

fromByteString :: ByteString -> SecureMem
fromByteString bs = unsafeDupablePerformIO $
                    B.unsafeUseAsCStringLen bs $ \(pbs, bsLen) ->
                    create bsLen $ \pdst ->
                    B.memcpy pdst (castPtr pbs) bsLen

toByteString :: SecureMem -> ByteString
toByteString sm = unsafeDupablePerformIO $
                  withSecureMemSz sm $ \i p ->
                  B.packCStringLen (castPtr p, i)

length :: SecureMem -> Int
length (SecureMem _ i) = i
