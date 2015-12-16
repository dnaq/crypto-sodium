{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TemplateHaskell   #-}
module Tests.Sodium.Sign.Ed25519 where

import           Tests.Sodium.Common

import qualified Crypto.Sodium.Box.Curve25519Xsalsa20Poly1305 as Curve25519
import           Crypto.Sodium.SecureMem
import           Crypto.Sodium.Sign.Ed25519

import           Control.Arrow
import           Control.Monad
import           Data.Attoparsec.ByteString                   as AP
import           Data.Attoparsec.ByteString.Char8             as A8
import           Data.ByteString                              (ByteString)
import qualified Data.ByteString                              as B
import           Data.Maybe
import           Data.Word
import           Test.QuickCheck.Monadic                      as QM
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck
import           Test.Tasty.TH

instance Arbitrary Seed where
  arbitrary = fromJust . mkSeed . fromByteString . B.pack <$>
              vector seedBytes

instance Arbitrary (PublicKey, SecretKey) where
  arbitrary = keypairFromSeed <$> arbitrary

case_secretKeyBytes :: Assertion
case_secretKeyBytes = 64 @=? secretKeyBytes

case_publicKeyBytes :: Assertion
case_publicKeyBytes = 32 @=? publicKeyBytes

case_signatureBytes :: Assertion
case_signatureBytes = 64 @=? signatureBytes

prop_mkPublicKey :: (PublicKey, SecretKey) -> Bool
prop_mkPublicKey (pk, _) = pk == fromJust (mkPublicKey $ unPublicKey pk)

prop_mkSecretKey :: (PublicKey, SecretKey) -> Bool
prop_mkSecretKey (_, sk) = sk == fromJust (mkSecretKey $ unSecretKey sk)

prop_mkSeed :: Seed -> Bool
prop_mkSeed s = s == fromJust (mkSeed $ unSeed s)

prop_randomSeed :: ByteString -> Property
prop_randomSeed m = monadicIO $ do
  (pk, sk) <- keypairFromSeed <$> run randomSeed
  QM.assert $ Just m == verify pk (sign sk m)

prop_randomKeypair :: Property
prop_randomKeypair = monadicIO $ do
  (pk, sk) <- run randomKeypair
  let s = skToSeed sk
  QM.assert $ (pk, sk) == keypairFromSeed s

prop_sign_verify :: (PublicKey, SecretKey) -> ByteString -> Bool
prop_sign_verify (pk, sk) m =
  let sm = sign sk m
      m' = verify pk sm
  in Just m == m'

prop_sign_verify_tamper :: (PublicKey, SecretKey) -> ByteString -> Int -> Positive Word8 -> Bool
prop_sign_verify_tamper (pk, sk) m i (Positive w) =
  let sm = sign sk m
      sm' = tamperAt i w sm
  in isNothing $ verify pk sm'

prop_sign_verify_detached :: (PublicKey, SecretKey) -> ByteString -> Bool
prop_sign_verify_detached (pk, sk) m =
  verifyDetached pk m (signDetached sk m)

prop_sign_verify_detached_tamper :: (PublicKey, SecretKey) -> ByteString -> Int -> Positive Word8 -> Bool
prop_sign_verify_detached_tamper (pk, sk) m i (Positive w) =
  let s = signDetached sk m
      m' = tamperAt i w m
      s' = fromJust . mkSignature . tamperAt i w . unSignature $ s
  in
    not (verifyDetached pk m s') && (not (verifyDetached pk m' s) || B.null m')

prop_sign_eq_sign_detached :: (PublicKey, SecretKey) -> ByteString -> Bool
prop_sign_eq_sign_detached (pk, sk) m =
  let sm = sign sk m
      s = signDetached sk m
  in unSignature s `B.append` m == sm &&
     isJust (verify pk sm) &&
     verifyDetached pk m s

prop_sk_to_seed_inverse :: (PublicKey, SecretKey) -> Bool
prop_sk_to_seed_inverse (_, sk) =
  let seed = skToSeed sk
      (_, sk') = keypairFromSeed seed
  in sk == sk'

prop_sk_to_pk :: (PublicKey, SecretKey) -> Bool
prop_sk_to_pk (pk, sk) = skToPk sk == pk

prop_keys_to_curve25519 :: (PublicKey, SecretKey)
                        -> (PublicKey, SecretKey)
                        -> Bool
prop_keys_to_curve25519 ourKeys theirKeys =
  let (ourPk, ourSk) = (pkToCurve25519 *** skToCurve25519) ourKeys
      (theirPk, theirSk) = (pkToCurve25519 *** skToCurve25519) theirKeys
      ourK = Curve25519.precompute ourSk theirPk
      theirK = Curve25519.precompute theirSk ourPk
  in ourK == theirK

data TestVector = TestVector { tvSeed :: !Seed
                             , tvPk   :: !PublicKey
                             , tvM    :: !ByteString
                             , tvSm   :: !ByteString
                             } deriving Show

testVector :: Parser TestVector
testVector = TestVector <$>
             (seed <* char ':') <*>
             (pk <* char ':') <*>
             (hexBs <* char ':') <*>
             (hexBs <* char ':')
  where
    seed = fromJust . mkSeed . fromByteString . B.take seedBytes <$> hexBs
    pk = fromJust . mkPublicKey <$> hexBs

vectorFile :: Parser [TestVector]
vectorFile = sepBy1 testVector (char '\n')

case_test_vectors :: Assertion
case_test_vectors = do
  Right vectors <- parseOnly vectorFile <$>
                   B.readFile "test/testvectors/ed25519.input"
  forM_ vectors $ \v -> do
    let (pk, sk) = keypairFromSeed (tvSeed v)
        sm = sign sk (tvM v)
    tvPk v @=? pk
    tvSm v @=? sm

tests :: TestTree
tests = $(testGroupGenerator)
