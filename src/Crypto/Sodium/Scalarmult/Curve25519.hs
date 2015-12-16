module Crypto.Sodium.Scalarmult.Curve25519
       ( scalarBytes
       , groupElementBytes
       , Scalar
       , mkScalar
       , unScalar
       , GroupElement
       , mkGroupElement
       , unGroupElement
       , scalarmult
       , scalarmultBase
       ) where

import           Crypto.Sodium.Internal  (mkSecureHelper)
import           Crypto.Sodium.SecureMem (SecureMem)
import qualified Crypto.Sodium.SecureMem as SM

import           Control.Monad           (void)
import           Data.Word               (Word8)
import           Foreign.C.Types         (CInt (..), CSize (..))
import           Foreign.Ptr             (Ptr)
import           System.IO.Unsafe        (unsafeDupablePerformIO)

foreign import ccall unsafe "crypto_scalarmult_curve25519_scalarbytes"
  c_crypto_scalarmult_curve25519_scalarbytes :: CSize

foreign import ccall unsafe "crypto_scalarmult_curve25519_bytes"
  c_crypto_scalarmult_curve25519_bytes:: CSize

foreign import ccall unsafe "crypto_scalarmult_curve25519"
  c_crypto_scalarmult_curve25519 :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_scalarmult_curve25519_base"
  c_crypto_scalarmult_curve25519_base :: Ptr Word8 -> Ptr Word8 -> IO CInt

scalarBytes :: Int
scalarBytes = fromIntegral c_crypto_scalarmult_curve25519_scalarbytes

groupElementBytes :: Int
groupElementBytes = fromIntegral c_crypto_scalarmult_curve25519_bytes

newtype Scalar = Scalar { unScalar :: SecureMem } deriving (Eq, Show)

mkScalar :: SecureMem -> Maybe Scalar
mkScalar = mkSecureHelper scalarBytes Scalar

newtype GroupElement = GroupElement { unGroupElement :: SecureMem}
                     deriving (Eq, Show)

mkGroupElement :: SecureMem -> Maybe GroupElement
mkGroupElement = mkSecureHelper groupElementBytes GroupElement

scalarmult :: Scalar -> GroupElement -> GroupElement
scalarmult (Scalar n) (GroupElement p) =
  GroupElement $
  unsafeDupablePerformIO $
  SM.create groupElementBytes $ \pq ->
  SM.withSecureMem n $ \pn ->
  SM.withSecureMem p $ \pp ->
  void $ c_crypto_scalarmult_curve25519 pq pn pp

scalarmultBase :: Scalar -> GroupElement
scalarmultBase (Scalar n) =
  GroupElement $
  unsafeDupablePerformIO $
  SM.create groupElementBytes $ \pq ->
  SM.withSecureMem n $ \pn ->
  void $ c_crypto_scalarmult_curve25519_base pq pn
