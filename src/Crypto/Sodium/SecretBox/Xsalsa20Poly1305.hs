{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{- |
See the documentation in "Crypto.Sodium.SecretBox".
-}
module Crypto.Sodium.SecretBox.Xsalsa20Poly1305
       ( -- * Constants
         keyBytes -- | Number of bytes in a 'Key'
       , nonceBytes -- | Number of bytes in a 'Nonce'

         -- * Types
       , Key -- | 'Key' for authenticated encryption
       , mkKey -- | Smart constructor for 'Key'
               --   returns 'Just' a 'Key' if the parameter is of length 'keyBytes'
       , unKey
       , Nonce -- | 'Nonce' for authenticated encryption
       , mkNonce -- | Smart constructor for 'Nonce'
                  --  returns 'Just' a 'Nonce' if the parameter is of length 'nonceBytes'
       , unNonce

         -- * Key Generation
       , randomKey -- | Randomly generates a 'Key'

         -- * Nonce Generation
       , randomNonce -- | Randomly generates a 'Nonce'

         -- * Sealing/Opening
       , seal -- | Encrypts and authenticates a message using a 'Key' and a 'Nonce'.
              --   It returns a ciphertext.
       , open -- | Verifies and decrypts a ciphertext using a 'Key' and a 'Nonce'.
              --   It returns a plaintext. If the ciphertext fails verification, 'open'
              --   returns 'Nothing'
       ) where

import           Crypto.Sodium.Internal  (marshal, mkHelper, mkSecureHelper,
                                          tryMarshal)
import           Crypto.Sodium.Random    (randomBytes, randomSecret)
import           Crypto.Sodium.SecureMem (SecureMem)
import qualified Crypto.Sodium.SecureMem as SM

import           Control.Monad           (void)
import           Data.ByteString         (ByteString)
import qualified Data.ByteString.Unsafe  as B
import           Data.Hashable           (Hashable)
import           Data.Word               (Word8)
import           Foreign.C.Types         (CChar, CInt (..), CSize (..),
                                          CULLong (..))
import           Foreign.Ptr             (Ptr)
import           System.IO.Unsafe        (unsafeDupablePerformIO)

foreign import ccall unsafe "crypto_secretbox_xsalsa20poly1305"
  c_crypto_secretbox_xsalsa20poly1305 :: Ptr Word8 -> Ptr Word8 -> CULLong -> Ptr CChar -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_secretbox_xsalsa20poly1305_open"
  c_crypto_secretbox_xsalsa20poly1305_open :: Ptr Word8 -> Ptr Word8 -> CULLong -> Ptr CChar -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_secretbox_xsalsa20poly1305_keybytes"
  c_crypto_secretbox_xsalsa20poly1305_keybytes :: CSize

foreign import ccall unsafe "crypto_secretbox_xsalsa20poly1305_noncebytes"
  c_crypto_secretbox_xsalsa20poly1305_noncebytes :: CSize

foreign import ccall unsafe "crypto_secretbox_xsalsa20poly1305_zerobytes"
  c_crypto_secretbox_xsalsa20poly1305_zerobytes :: CSize

foreign import ccall unsafe "crypto_secretbox_xsalsa20poly1305_boxzerobytes"
  c_crypto_secretbox_xsalsa20poly1305_boxzerobytes :: CSize

keyBytes :: Int
keyBytes = fromIntegral c_crypto_secretbox_xsalsa20poly1305_keybytes

nonceBytes :: Int
nonceBytes = fromIntegral c_crypto_secretbox_xsalsa20poly1305_noncebytes

zeroBytes :: Int
zeroBytes = fromIntegral c_crypto_secretbox_xsalsa20poly1305_zerobytes

boxZeroBytes :: Int
boxZeroBytes = fromIntegral c_crypto_secretbox_xsalsa20poly1305_boxzerobytes

newtype Key = Key { unKey :: SecureMem } deriving (Eq, Show)

newtype Nonce = Nonce { unNonce :: ByteString }
              deriving (Eq, Show, Ord, Hashable)

randomKey :: IO Key
randomKey = Key <$> randomSecret keyBytes

randomNonce :: IO Nonce
randomNonce = Nonce <$> randomBytes nonceBytes

mkKey :: SecureMem -> Maybe Key
mkKey = mkSecureHelper keyBytes Key

mkNonce :: ByteString -> Maybe Nonce
mkNonce = mkHelper nonceBytes Nonce

seal :: Key -> Nonce -> ByteString -> ByteString
seal (Key k) (Nonce n) m =
  unsafeDupablePerformIO $
  marshal zeroBytes boxZeroBytes m $ \cLen pc ->
  B.unsafeUseAsCString n $ \pn ->
  SM.withSecureMem k $ \pk ->
  void $ c_crypto_secretbox_xsalsa20poly1305 pc pc (fromIntegral cLen) pn pk

open :: Key -> Nonce -> ByteString -> Maybe ByteString
open (Key k) (Nonce n) c =
  unsafeDupablePerformIO $
  tryMarshal boxZeroBytes zeroBytes c $ \mLen pm ->
  B.unsafeUseAsCString n $ \pn ->
  SM.withSecureMem k $ \pk ->
  c_crypto_secretbox_xsalsa20poly1305_open pm pm (fromIntegral mLen) pn pk
