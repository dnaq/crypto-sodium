{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{- |
See the documentation in "Crypto.Sodium.Box".
-}
module Crypto.Sodium.Box.Curve25519Xsalsa20Poly1305
       (-- * Constants
         publicKeyBytes -- | Number of bytes in a 'PublicKey'.
       , secretKeyBytes -- | Number of bytes in a 'SecretKey'.
       , nonceBytes -- | Number of bytes in a 'Nonce'.
       , precomputedKeyBytes -- | Number of bytes in a 'PrecomputedKey'.
       , seedBytes -- | Number of bytes in a 'Seed'.

         -- * Types
       , PublicKey -- | 'PublicKey' for asymmetric authenticated encryption.
       , mkPublicKey -- | Smart constructor for 'PublicKey'. Verifies
                     -- that the length of the parameter is 'publicKeyBytes'.
       , unPublicKey -- | Returns the contents of a 'PublicKey'.
       , SecretKey -- | 'SecretKey' for asymmetric authenticated encryption.
       , mkSecretKey -- | Smart constructor for 'SecretKey'. Verifies that the
                     -- length of the parameter is 'secretKeyBytes'.
       , unSecretKey -- | Returns the contents of a 'SecretKey'.
       , Nonce -- | 'Nonce' for asymmetric authenticated encryption.
       , mkNonce -- | Smart constructor for 'Nonce'. Verifies that the length of
                 -- the parameter is 'nonceBytes'.
       , unNonce -- | Returns the contents of a 'Nonce'.
       , PrecomputedKey -- | 'PrecomputedKey' for asymmetric authenticated
                        -- encryption.
       , mkPrecomputedKey -- | Smart constructor for 'PrecomputedKey'. Verifies
                          -- that the length of the parameter is
                          -- 'precomputedKeyBytes'.
       , unPrecomputedKey -- | Returns the contents of a 'PrecomputedKey'.
       , Seed -- | 'Seed' for deterministic key generation.
       , mkSeed -- | Smart constructor for 'Seed'. Verifies that the length of
                -- the parameter is 'seedBytes'.
       , unSeed -- | Returns the contents of a 'Seed'.

         -- * Key Generation
       , randomKeypair -- | Randomly generates a 'SecretKey' and the corresponding 'PublicKey'.
       , keypairFromSeed -- | Computes a 'SecretKey' and the corresponding
                         -- 'PublicKey' from a 'Seed'.
       , randomSeed -- | Randomly generates a 'Seed'.

         -- * Nonce Generation
       , randomNonce -- | Randomly generates a 'Nonce'.

         -- * Sealing/Opening
       , seal -- | Encrypts and authenticates a message using the senders
              -- 'SecretKey', the receivers 'PublicKey', and a 'Nonce'.
              -- It returns a ciphertext.
       , open -- | Verifies and decrypts a ciphertext using the receivers
              -- 'SecretKey', the senders 'PublicKey', and a 'Nonce'.
              -- It returns a plaintext. If the ciphertext fails verification,
              -- 'open' returns 'Nothing'.

         -- * Precomputation Interface
         -- | Applications that send several messages to the same receiver can
         -- gain speed by splitting 'seal' into two steps, 'precompute'
         -- and 'sealPrecomputed'. Similarly, applications that receive several
         -- messages from the same sender can gain speed by splitting 'open'
         -- into two steps, 'precompute' and 'openPrecomputed'.
       , precompute -- | Computes an intermediate key that can be used by
                    -- 'sealPrecomputed' and 'openPrecomputed'.
       , sealPrecomputed -- | Encrypts and authenticates a message using a
                         -- 'PrecomputedKey'. Returns a ciphertext.
       , openPrecomputed -- | Verifies and decrypts a ciphertext using a
                         -- 'PrecomputedKey'. Returns a plaintext.
                         -- If the ciphertext fails verification
                         -- 'openPrecomputed' returns 'Nothing'.
       ) where

import           Crypto.Sodium.Internal  (createWithResult, marshal, mkHelper,
                                          mkSecureHelper, tryMarshal)
import           Crypto.Sodium.Random    (randomBytes, randomSecret)
import           Crypto.Sodium.SecureMem (SecureMem)
import qualified Crypto.Sodium.SecureMem as SM

import           Control.Arrow           ((***))
import           Control.Monad           (void)
import           Data.ByteString         (ByteString)
import qualified Data.ByteString.Unsafe  as B
import           Data.Hashable           (Hashable)
import           Data.Word               (Word8)
import           Foreign.C.Types         (CChar, CInt (..), CSize (..),
                                          CULLong (..))
import           Foreign.Ptr             (Ptr)
import           System.IO.Unsafe        (unsafeDupablePerformIO)

foreign import ccall unsafe "crypto_box_curve25519xsalsa20poly1305_seedbytes"
  c_crypto_box_curve25519xsalsa20poly1305_seedbytes :: CSize

foreign import ccall unsafe "crypto_box_curve25519xsalsa20poly1305_publickeybytes"
  c_crypto_box_curve25519xsalsa20poly1305_publickeybytes :: CSize

foreign import ccall unsafe "crypto_box_curve25519xsalsa20poly1305_secretkeybytes"
  c_crypto_box_curve25519xsalsa20poly1305_secretkeybytes :: CSize

foreign import ccall unsafe "crypto_box_curve25519xsalsa20poly1305_beforenmbytes"
  c_crypto_box_curve25519xsalsa20poly1305_beforenmbytes :: CSize

foreign import ccall unsafe "crypto_box_curve25519xsalsa20poly1305_noncebytes"
  c_crypto_box_curve25519xsalsa20poly1305_noncebytes :: CSize

foreign import ccall unsafe "crypto_box_curve25519xsalsa20poly1305_zerobytes"
  c_crypto_box_curve25519xsalsa20poly1305_zerobytes :: CSize

foreign import ccall unsafe "crypto_box_curve25519xsalsa20poly1305_boxzerobytes"
  c_crypto_box_curve25519xsalsa20poly1305_boxzerobytes :: CSize

foreign import ccall unsafe "crypto_box_curve25519xsalsa20poly1305"
  c_crypto_box_curve25519xsalsa20poly1305 :: Ptr Word8 -> Ptr Word8 -> CULLong -> Ptr CChar -> Ptr CChar -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_box_curve25519xsalsa20poly1305_open"
  c_crypto_box_curve25519xsalsa20poly1305_open :: Ptr Word8 -> Ptr Word8 -> CULLong -> Ptr CChar -> Ptr CChar -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_box_curve25519xsalsa20poly1305_seed_keypair"
  c_crypto_box_curve25519xsalsa20poly1305_seed_keypair :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_box_curve25519xsalsa20poly1305_keypair"
  c_crypto_box_curve25519xsalsa20poly1305_keypair :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_box_curve25519xsalsa20poly1305_beforenm"
  c_crypto_box_curve25519xsalsa20poly1305_beforenm :: Ptr Word8 -> Ptr CChar -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_box_curve25519xsalsa20poly1305_afternm"
  c_crypto_box_curve25519xsalsa20poly1305_afternm :: Ptr Word8 -> Ptr Word8 -> CULLong -> Ptr CChar -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_box_curve25519xsalsa20poly1305_open_afternm"
  c_crypto_box_curve25519xsalsa20poly1305_open_afternm :: Ptr Word8 -> Ptr Word8 -> CULLong -> Ptr CChar -> Ptr Word8 -> IO CInt

publicKeyBytes :: Int
publicKeyBytes = fromIntegral c_crypto_box_curve25519xsalsa20poly1305_publickeybytes

secretKeyBytes :: Int
secretKeyBytes = fromIntegral c_crypto_box_curve25519xsalsa20poly1305_secretkeybytes

nonceBytes :: Int
nonceBytes = fromIntegral c_crypto_box_curve25519xsalsa20poly1305_noncebytes

precomputedKeyBytes :: Int
precomputedKeyBytes = fromIntegral c_crypto_box_curve25519xsalsa20poly1305_beforenmbytes

zeroBytes :: Int
zeroBytes = fromIntegral c_crypto_box_curve25519xsalsa20poly1305_zerobytes

boxZeroBytes :: Int
boxZeroBytes = fromIntegral c_crypto_box_curve25519xsalsa20poly1305_boxzerobytes

seedBytes :: Int
seedBytes = fromIntegral c_crypto_box_curve25519xsalsa20poly1305_seedbytes

newtype PublicKey = PublicKey {
  unPublicKey :: ByteString
  } deriving (Eq, Show, Ord, Hashable)

mkPublicKey :: ByteString -> Maybe PublicKey
mkPublicKey = mkHelper publicKeyBytes PublicKey

newtype SecretKey = SecretKey {
  unSecretKey :: SecureMem
  } deriving (Eq, Show)

mkSecretKey :: SecureMem -> Maybe SecretKey
mkSecretKey = mkSecureHelper secretKeyBytes SecretKey

newtype Nonce = Nonce {
  unNonce :: ByteString
  } deriving (Eq, Show, Ord, Hashable)

mkNonce :: ByteString -> Maybe Nonce
mkNonce = mkHelper nonceBytes Nonce

newtype PrecomputedKey = PrecomputedKey {
  unPrecomputedKey :: SecureMem
  } deriving (Eq, Show)

mkPrecomputedKey :: SecureMem -> Maybe PrecomputedKey
mkPrecomputedKey = mkSecureHelper precomputedKeyBytes PrecomputedKey

newtype Seed = Seed {
  unSeed :: SecureMem
  } deriving (Eq, Show)

mkSeed :: SecureMem -> Maybe Seed
mkSeed = mkSecureHelper seedBytes Seed

randomKeypair :: IO (PublicKey, SecretKey)
randomKeypair = fmap (PublicKey *** SecretKey) $
  createWithResult publicKeyBytes $ \ppk ->
  SM.create secretKeyBytes $ \psk ->
  void $ c_crypto_box_curve25519xsalsa20poly1305_keypair ppk psk

keypairFromSeed :: Seed -> (PublicKey, SecretKey)
keypairFromSeed (Seed s) = (PublicKey *** SecretKey) $ unsafeDupablePerformIO $
  createWithResult publicKeyBytes $ \ppk ->
  SM.create secretKeyBytes $ \psk ->
  SM.withSecureMem s $ \ps ->
  void $ c_crypto_box_curve25519xsalsa20poly1305_seed_keypair ppk psk ps

randomSeed :: IO Seed
randomSeed = Seed <$> randomSecret seedBytes

randomNonce :: IO Nonce
randomNonce = Nonce <$> randomBytes nonceBytes

seal :: SecretKey -- ^ The senders 'SecretKey'.
     -> PublicKey -- ^ The receivers 'PublicKey'.
     -> Nonce
     -> ByteString -- ^ The message.
     -> ByteString -- ^ The ciphertext.
seal (SecretKey sk) (PublicKey pk) (Nonce n) m =
  unsafeDupablePerformIO $
  marshal zeroBytes boxZeroBytes m $ \cLen pc ->
  B.unsafeUseAsCString n $ \pn ->
  B.unsafeUseAsCString pk $ \ppk ->
  SM.withSecureMem sk $ \psk ->
  void $ c_crypto_box_curve25519xsalsa20poly1305 pc pc (fromIntegral cLen) pn ppk psk

open :: SecretKey -- ^ The receivers 'SecretKey'.
     -> PublicKey -- ^ The senders 'PublicKey'.
     -> Nonce
     -> ByteString -- ^ The ciphertext.
     -> Maybe ByteString -- ^ The plaintext.
open (SecretKey sk) (PublicKey pk) (Nonce n) c =
  unsafeDupablePerformIO $
  tryMarshal boxZeroBytes zeroBytes c $ \mLen pm ->
  B.unsafeUseAsCString n $ \pn ->
  B.unsafeUseAsCString pk $ \ppk ->
  SM.withSecureMem sk $ \psk ->
  c_crypto_box_curve25519xsalsa20poly1305_open pm pm (fromIntegral mLen) pn ppk psk

precompute :: SecretKey -- ^ Our 'SecretKey'
           -> PublicKey -- ^ Their 'PublicKey'
           -> PrecomputedKey
precompute (SecretKey sk) (PublicKey pk) =
  PrecomputedKey $
  unsafeDupablePerformIO $
  SM.create precomputedKeyBytes $ \k ->
  B.unsafeUseAsCString pk $ \ppk ->
  SM.withSecureMem sk $
  void . c_crypto_box_curve25519xsalsa20poly1305_beforenm k ppk

sealPrecomputed :: PrecomputedKey
                -> Nonce
                -> ByteString -- ^ The message.
                -> ByteString -- ^ The ciphertext.
sealPrecomputed (PrecomputedKey k) (Nonce n) m =
  unsafeDupablePerformIO $
  marshal zeroBytes boxZeroBytes m $ \cLen pc ->
  B.unsafeUseAsCString n $ \pn ->
  SM.withSecureMem k $ \pk ->
  void $ c_crypto_box_curve25519xsalsa20poly1305_afternm pc pc (fromIntegral cLen) pn pk

openPrecomputed :: PrecomputedKey -> Nonce
                -> ByteString -- ^ The ciphertext.
                -> Maybe ByteString -- ^ The plaintext.
openPrecomputed (PrecomputedKey k) (Nonce n) c =
  unsafeDupablePerformIO $
  tryMarshal boxZeroBytes zeroBytes c $ \mLen pm ->
  B.unsafeUseAsCString n $ \pn ->
  SM.withSecureMem k $ \pk ->
  c_crypto_box_curve25519xsalsa20poly1305_open_afternm pm pm (fromIntegral mLen) pn pk
