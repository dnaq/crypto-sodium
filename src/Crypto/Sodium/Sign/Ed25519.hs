{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{- |
See the documentation in "Crypto.Sodium.Sign".
-}
module Crypto.Sodium.Sign.Ed25519
       ( -- * Constants
         publicKeyBytes -- | Number of bytes in a 'PublicKey'.
       , secretKeyBytes -- | Number of bytes in a 'SecretKey'.
       , seedBytes -- | Number of bytes in a 'Seed'.
       , signatureBytes -- | Number of bytes in a 'Signature'.

         -- * Types
       , PublicKey -- | 'PublicKey' for asymmetric signing.
       , mkPublicKey -- | Smart constructor for 'PublicKey'. Verifies that
                     -- the length of the parameter is 'publicKeyBytes'.
       , unPublicKey -- | Returns the contents of a 'PublicKey'.
       , SecretKey -- | 'SecretKey' for asymmetric signing.
       , mkSecretKey -- | Smart constructor for 'SecretKey'. Verifies that
                     -- the length of the parameter is 'secretKeyBytes'.
       , unSecretKey -- | Returns the contents of a 'SecretKey'.
       , Seed -- | 'Seed' for deterministic key generation.
       , mkSeed -- | Smart constructor for 'Seed'. Verifies that the length of
                -- the parameter is 'seedBytes'.
       , unSeed -- | Returns the contents of a 'Seed'.
       , Signature -- | A 'Signature' of a message.
       , mkSignature -- | Smart constructor for 'Signature'. Verifies that
                     -- the length of the parameter is 'signatureBytes'.
       , unSignature -- | Returns the contents of a 'Signature'.

         -- * Key Generation
       , randomKeypair -- | Randomly generates a 'SecretKey' and the corresponding
                       -- 'PublicKey'.
       , keypairFromSeed -- | Computes a 'SecretKey' and the corresponding
                         -- 'PublicKey' from a 'Seed'.
       , randomSeed -- | Randomly generates a 'Seed'.

         -- * Signing/Verifying
       , sign -- | Signs a message using a 'SecretKey'. Returns the signed message.
       , verify -- | Verifies that a message has been signed by the 'SecretKey'
                -- corresponding to the 'PublicKey' given as a parameter.
                -- If verification succeeds it returns 'Just' the
                -- contents of the message, otherwise it returns 'Nothing'.
       , signDetached -- | Signs a message using a 'SecretKey'. Returns a detached
                      -- 'Signature'.
       , verifyDetached -- | Verifies that a message with a detached 'Signature' has
                        -- been signed by the 'SecretKey' corresponding to the
                        -- 'PublicKey' given as a parameter.

         -- * Key Conversion
       , skToSeed -- | Converts a 'SecretKey' to a 'Seed'.
       , skToPk -- | Computes the corresponding 'PublicKey' from a 'SecretKey'.
       , pkToCurve25519 -- | Converts a 'PublicKey' to a 'Curve25519.PublicKey'
                        -- for use in asymmetric authenticated encryption.
                        --
                        -- WARNING: This function should only be used if
                        -- you are absolutely sure of what you're doing.
                        -- Using the same key for different purposes will
                        -- open up for cross protocol attacks unless you're
                        -- extremely careful.
       , skToCurve25519 -- | Converts a 'SecretKey' to a 'Curve25519.SecretKey'
                        -- for use in asymmetric authenticated encryption.
                        --
                        -- WARNING: This function should only be used if
                        -- you are absolutely sure of what you're doing.
                        -- Using the same key for different purposes will
                        -- open up for cross protocol attacks unless you're
                        -- extremely careful.
       ) where

import qualified Crypto.Sodium.Box.Curve25519Xsalsa20Poly1305 as Curve
import           Crypto.Sodium.Internal                       (createWithResult,
                                                               mkHelper,
                                                               mkSecureHelper)
import           Crypto.Sodium.Random                         (randomSecret)
import           Crypto.Sodium.SecureMem                      (SecureMem)
import qualified Crypto.Sodium.SecureMem                      as SM

import           Control.Arrow                                ((***))
import           Control.Exception                            (evaluate)
import           Control.Monad                                (unless, void,
                                                               (<=<))
import           Data.ByteString                              (ByteString)
import qualified Data.ByteString                              as B
import qualified Data.ByteString.Internal                     as B
import qualified Data.ByteString.Unsafe                       as B
import           Data.Hashable                                (Hashable)
import           Data.Maybe                                   (fromJust)
import           Data.Word                                    (Word8)
import           Foreign.C.Types                              (CChar, CInt (..),
                                                               CSize (..),
                                                               CULLong (..))
import           Foreign.Marshal.Alloc                        (alloca)
import           Foreign.Ptr                                  (Ptr)
import           Foreign.Storable                             (peek)
import           System.IO.Unsafe                             (unsafeDupablePerformIO)

foreign import ccall unsafe "crypto_sign_ed25519_bytes"
  c_crypto_sign_ed25519_bytes :: CSize

foreign import ccall unsafe "crypto_sign_ed25519_seedbytes"
  c_crypto_sign_ed25519_seedbytes :: CSize

foreign import ccall unsafe "crypto_sign_ed25519_publickeybytes"
  c_crypto_sign_ed25519_publickeybytes :: CSize

foreign import ccall unsafe "crypto_sign_ed25519_secretkeybytes"
  c_crypto_sign_ed25519_secretkeybytes :: CSize

foreign import ccall unsafe "crypto_sign_ed25519"
    c_crypto_sign_ed25519 :: Ptr Word8 -> Ptr CULLong -> Ptr CChar -> CULLong -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_sign_ed25519_open"
  c_crypto_sign_ed25519_open :: Ptr Word8 -> Ptr CULLong -> Ptr CChar -> CULLong -> Ptr CChar -> IO CInt

foreign import ccall unsafe "crypto_sign_ed25519_detached"
  c_crypto_sign_ed25519_detached :: Ptr Word8 -> Ptr CULLong -> Ptr CChar -> CULLong -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_sign_ed25519_verify_detached"
  c_crypto_sign_ed25519_verify_detached :: Ptr CChar -> Ptr CChar -> CULLong -> Ptr CChar -> IO CInt

foreign import ccall unsafe "crypto_sign_ed25519_keypair"
  c_crypto_sign_ed25519_keypair :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_sign_ed25519_seed_keypair"
  c_crypto_sign_ed25519_seed_keypair :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_sign_ed25519_pk_to_curve25519"
  c_crypto_sign_ed25519_pk_to_curve25519 :: Ptr Word8 -> Ptr CChar -> IO CInt

foreign import ccall unsafe "crypto_sign_ed25519_sk_to_curve25519"
  c_crypto_sign_ed25519_sk_to_curve25519 :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_sign_ed25519_sk_to_seed"
  c_crypto_sign_ed25519_sk_to_seed :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "crypto_sign_ed25519_sk_to_pk"
  c_crypto_sign_ed25519_sk_to_pk :: Ptr Word8 -> Ptr Word8 -> IO CInt

seedBytes :: Int
seedBytes = fromIntegral c_crypto_sign_ed25519_seedbytes

secretKeyBytes :: Int
secretKeyBytes = fromIntegral c_crypto_sign_ed25519_secretkeybytes

publicKeyBytes :: Int
publicKeyBytes = fromIntegral c_crypto_sign_ed25519_publickeybytes

signatureBytes :: Int
signatureBytes = fromIntegral c_crypto_sign_ed25519_bytes

newtype Seed = Seed { unSeed :: SecureMem } deriving (Eq, Show)

mkSeed :: SecureMem -> Maybe Seed
mkSeed = mkSecureHelper seedBytes Seed

newtype SecretKey = SecretKey { unSecretKey :: SecureMem } deriving (Eq, Show)

mkSecretKey :: SecureMem -> Maybe SecretKey
mkSecretKey = mkSecureHelper secretKeyBytes SecretKey

newtype PublicKey = PublicKey { unPublicKey :: ByteString } deriving (Eq, Show, Ord, Hashable)

mkPublicKey :: ByteString -> Maybe PublicKey
mkPublicKey = mkHelper publicKeyBytes PublicKey

newtype Signature = Signature { unSignature :: ByteString } deriving (Eq, Show)

mkSignature :: ByteString -> Maybe Signature
mkSignature = mkHelper signatureBytes Signature

randomSeed :: IO Seed
randomSeed = Seed <$> randomSecret seedBytes

randomKeypair :: IO (PublicKey, SecretKey)
randomKeypair =
  fmap (PublicKey *** SecretKey) $
  createWithResult publicKeyBytes $ \ppk ->
  SM.create secretKeyBytes $ \psk ->
  void $ c_crypto_sign_ed25519_keypair ppk psk

keypairFromSeed :: Seed -> (PublicKey, SecretKey)
keypairFromSeed (Seed s) =
  (PublicKey *** SecretKey) $
  unsafeDupablePerformIO $
  createWithResult publicKeyBytes $ \ppk ->
  SM.create secretKeyBytes $ \psk ->
  SM.withSecureMem s $ \ps ->
  void $ c_crypto_sign_ed25519_seed_keypair ppk psk ps

sign :: SecretKey -> ByteString -> ByteString
sign (SecretKey sk) m =
  unsafeDupablePerformIO $
  B.unsafeUseAsCStringLen m $ \(pm, mLen) ->
  alloca $ \psmLen ->
  SM.withSecureMem sk $ \psk -> do
    sm <- B.create (mLen + signatureBytes) $ \psm ->
      void $ c_crypto_sign_ed25519 psm psmLen pm (fromIntegral mLen) psk
    (`B.take` sm) . fromIntegral <$> peek psmLen

verify :: PublicKey -> ByteString -> Maybe ByteString
verify (PublicKey pk) sm =
  unsafeDupablePerformIO $
  B.unsafeUseAsCStringLen sm $ \(psm, smLen) ->
  alloca $ \pmLen ->
  B.unsafeUseAsCString pk $ \ppk -> do
    (m, r) <- createWithResult smLen $ \pm ->
      c_crypto_sign_ed25519_open pm pmLen psm (fromIntegral smLen) ppk
    if r == 0
      then Just . (`B.take` m) . fromIntegral <$> peek pmLen
      else return Nothing

signDetached :: SecretKey -> ByteString -> Signature
signDetached (SecretKey sk) m =
  Signature $ B.unsafeCreate signatureBytes $ \ps ->
  alloca $ \psLen ->
  B.unsafeUseAsCStringLen m $ \(pm, mLen) ->
  SM.withSecureMem sk $ \psk -> do
    void $ c_crypto_sign_ed25519_detached ps psLen pm (fromIntegral mLen) psk
    sLen <- fromIntegral <$> peek psLen
    unless (sLen == signatureBytes) $
      evaluate $ error "signDetached: internal error sLen /= signatureBytes"

verifyDetached :: PublicKey -> ByteString -> Signature -> Bool
verifyDetached (PublicKey pk) m (Signature s) =
  unsafeDupablePerformIO $
  B.unsafeUseAsCString s $ \ps ->
  B.unsafeUseAsCStringLen m $ \(pm, mLen) ->
  B.unsafeUseAsCString pk $
  return . (==0) <=<
  c_crypto_sign_ed25519_verify_detached ps pm (fromIntegral mLen)

pkToCurve25519 :: PublicKey -> Curve.PublicKey
pkToCurve25519 (PublicKey pk) =
  fromJust $
  Curve.mkPublicKey $
  B.unsafeCreate Curve.publicKeyBytes $ \pcpk ->
  B.unsafeUseAsCString pk $
  void . c_crypto_sign_ed25519_pk_to_curve25519 pcpk

skToCurve25519 :: SecretKey -> Curve.SecretKey
skToCurve25519 (SecretKey sk) =
  fromJust $
  Curve.mkSecretKey $
  unsafeDupablePerformIO $
  SM.create Curve.secretKeyBytes $ \pcsk ->
  SM.withSecureMem sk $
  void . c_crypto_sign_ed25519_sk_to_curve25519 pcsk

skToSeed :: SecretKey -> Seed
skToSeed (SecretKey sk) =
  Seed $
  unsafeDupablePerformIO $
  SM.create seedBytes $ \ps ->
  SM.withSecureMem sk $
  void . c_crypto_sign_ed25519_sk_to_seed ps

skToPk :: SecretKey -> PublicKey
skToPk (SecretKey sk) =
  PublicKey $
  B.unsafeCreate publicKeyBytes $ \ppk ->
  SM.withSecureMem sk $
  void . c_crypto_sign_ed25519_sk_to_pk ppk
