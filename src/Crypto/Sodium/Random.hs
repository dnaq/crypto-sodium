{- |
= Cryptographic Random Number Generation
-}
module Crypto.Sodium.Random (randomBytes, randomSecret) where

import           Crypto.Sodium.SecureMem  (SecureMem)
import qualified Crypto.Sodium.SecureMem  as SM
import           Data.ByteString          (ByteString)
import qualified Data.ByteString.Internal as B
import           Data.Word                (Word8)
import           Foreign.C.Types          (CULLong (..))
import           Foreign.Ptr              (Ptr)

foreign import ccall unsafe "randombytes"
    c_randombytes :: Ptr Word8 -> CULLong -> IO ()

-- | Randomly generate data.
randomBytes :: Int -- ^ Number of bytes to generate
            -> IO ByteString
randomBytes i = B.create i $ flip c_randombytes (fromIntegral i)

-- | Randomly generate data, returned as a 'SecureMem'.
randomSecret :: Int -- ^ Number of bytes to generate
             -> IO SecureMem
randomSecret i = SM.create i $ flip c_randombytes (fromIntegral i)
