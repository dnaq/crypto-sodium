{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Tests.Sodium.Auth.Common where

import           Tests.Sodium.Common

import           Crypto.Sodium.Auth.Internal
import           Crypto.Sodium.SecureMem

import qualified Data.ByteString             as B
import           Data.Maybe
import           Data.Word
import           Test.QuickCheck.Monadic     as QM
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck

mkTests :: forall a. Auth a
        -> [([Word8], [Word8], [Word8])]
        -> [TestTree]
mkTests Auth {..} vectors =
    testProperty "random key" prop_RandomKey :
    testProperty "auth verify" prop_AuthVerify :
    testProperty "auth verify tamper" prop_AuthVerifyTamper :
    map testVectorAuth vectors
    where
      mkTag' = fromJust . mkTag . B.pack

      arbitraryKey :: Gen (Key a)
      arbitraryKey = fromJust . mkKey . fromByteString . B.pack <$> vector keyBytes

      prop_RandomKey = monadicIO $ do
        k <- run randomKey
        QM.assert (fromByteString (B.replicate keyBytes 0) /= unKey k)

      prop_AuthVerify m = forAll arbitraryKey $ \k -> verify k m (authenticate k m)
      prop_AuthVerifyTamper m i (Positive w) =
          forAll arbitraryKey $ \k ->
          let t = authenticate k m
              t' = fromJust $ mkTag $ tamperAt i w $ unTag t
              m' = tamperAt i w m
          in not (verify k m t') && (not (verify k m' t) || B.null m) &&
             not (verify k m' t')

      testVectorAuth (k, c, aexp) = testCase "vector" $ do
        let key = fromJust . mkKey . fromByteString . B.pack $ k
            a = authenticate key (B.pack c)
        mkTag' aexp @=? a
