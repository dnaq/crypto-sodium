{- |
A module containing semi-public internals.
-}
module Crypto.Sodium.Internal
       ( constantTimeEq
       , createWithResult
       , marshal
       , mkHelper
       , mkSecureHelper
       , tryMarshal
       )
       where

import           Crypto.Sodium.SecureMem  (SecureMem)
import qualified Crypto.Sodium.SecureMem  as SM

import           Control.Monad            (void)
import           Data.ByteString          (ByteString)
import qualified Data.ByteString          as B
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Unsafe   as B
import           Data.Word                (Word8)
import           Foreign.C.Types          (CChar, CInt (..), CSize (..))
import           Foreign.ForeignPtr       (withForeignPtr)
import           Foreign.Ptr              (Ptr, castPtr, plusPtr)
import           System.IO.Unsafe         (unsafeDupablePerformIO)

foreign import ccall unsafe "sodium_memcmp"
  c_sodium_memcmp :: Ptr CChar -> Ptr CChar -> CSize -> IO CInt

-- | Verifies that two ByteStrings are equal in constant time.
constantTimeEq :: ByteString -> ByteString -> Bool
constantTimeEq x y
  | xLen /= yLen = False
  | otherwise = (==0) $ unsafeDupablePerformIO $
                B.unsafeUseAsCString x $ \px ->
                B.unsafeUseAsCString y $ \py ->
                c_sodium_memcmp px py (fromIntegral xLen)
  where
    xLen = B.length x
    yLen = B.length y

-- | Creates a 'ByteString' from an 'IO' action and returns the
-- created 'ByteString' and the result from the 'IO' action.
createWithResult :: Int -> (Ptr Word8 -> IO a) -> IO (ByteString, a)
createWithResult i f = do
  fp <- B.mallocByteString i
  r <- withForeignPtr fp f
  return (B.fromForeignPtr fp 0 i, r)

-- Helper function for marshalling
marshal' :: Int -> Int -> ByteString
         -> (Int -> Ptr Word8 -> IO a)
         -> IO (ByteString, a)
marshal' pad unPad bs f = B.unsafeUseAsCStringLen bs $ \(p, len) -> do
  let len' = pad + len
  fp <- B.mallocByteString len'
  withForeignPtr fp $ \p' -> do
    void $ B.memset p' 0 (fromIntegral pad)
    B.memcpy (p' `plusPtr` pad) (castPtr p) len
    r <- f len' p'
    return (B.fromForeignPtr fp unPad (len' - unPad), r)

-- | Marshal a 'ByteString' for use by the low level functions in box/secretbox.
--
-- Pre-pads a 'ByteString' with 'pad' zeroes, runs the 'IO' action on the length
-- and underlying pointer of the 'ByteString' and drops 'unPad' bytes from the
-- beginning of the resulting 'ByteString'.
marshal :: Int -- ^ 'pad': number of zeroes to pre-pad with
        -> Int -- ^ 'unPad': number of bytes to drop
        -> ByteString
        -> (Int -> Ptr Word8 -> IO ())
        -> IO ByteString
marshal pad unPad bs = fmap fst . marshal' pad unPad bs

-- | Marshal a 'ByteString' for use by the low level functions in box/secretbox.
--
-- Pre-pads a 'ByteString' with 'pad' zeroes and runs the 'IO' action on the length
-- and underlying pointer of the 'ByteString'. If the 'IO' action returns 0
-- drops 'unPad' bytes from the beginning of the resulting 'ByteString', otherwise
-- returns 'Nothing'.
tryMarshal :: Int -> Int -> ByteString
           -> (Int -> Ptr Word8 -> IO CInt)
           -> IO (Maybe ByteString)
tryMarshal pad unPad bs f = marshal' pad unPad bs f >>= go
  where
    go (x, 0) = return $ Just x
    go _ = return Nothing

-- | Helper function for creating smart constructors.
--
-- @
-- nonceBytes :: Int
-- nonceBytes = 32
--
-- newtype Nonce = Nonce { unNonce :: ByteString}
--
-- mkNonce :: Nonce -> Maybe Nonce
-- mkNonce = mkHelper nonceBytes Nonce
-- @
mkHelper :: Int -- ^ Expected byte length of argument.
         -> (ByteString -> a) -- ^ Function to call if argument is of the correct length.
         -> ByteString
         -> Maybe a
mkHelper i f bs
  | B.length bs == i = Just (f bs)
  | otherwise = Nothing
{-# INLINE mkHelper #-}

-- | Helper function for creating smart constructors.
--
-- @
-- keyBytes :: Int
-- keyBytes = 32
--
-- newtype Key = Key { unKey :: SecureMem }
--
-- mkKey :: SecureMem -> Maybe Key
-- mkKey = mkHelper keyBytes Key
-- @
mkSecureHelper :: Int -> (SecureMem -> a) -> SecureMem -> Maybe a
mkSecureHelper i f sm
  | SM.length sm == i = Just (f sm)
  | otherwise = Nothing
{-# INLINE mkSecureHelper #-}
