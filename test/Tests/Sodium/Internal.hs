{-# LANGUAGE TemplateHaskell #-}
module Tests.Sodium.Internal where

import           Tests.Sodium.Common     ()

import           Crypto.Sodium.Internal
import qualified Crypto.Sodium.SecureMem as SM

import           Data.ByteString         (ByteString)
import qualified Data.ByteString         as B
import           Data.Maybe
import           Test.Tasty
import           Test.Tasty.QuickCheck
import           Test.Tasty.TH

prop_constantTimeEq :: ByteString -> ByteString -> Bool
prop_constantTimeEq bs1 bs2 = constantTimeEq bs1 bs2 == (bs1 == bs2)

prop_mkHelper_correct_length :: Positive Int -> Property
prop_mkHelper_correct_length (Positive i) = forAll (vector i) $ \v ->
  isJust $ mkHelper i id (B.pack v)

prop_mkHelper :: Positive Int -> ByteString -> Bool
prop_mkHelper (Positive i) bs =
  isJust (mkHelper i id bs) == (i == B.length bs)

prop_mkSecureHelper_correct_length :: Positive Int -> Property
prop_mkSecureHelper_correct_length (Positive i) =
  forAll (SM.fromByteString . B.pack <$> vector i) $ \sm ->
  isJust $ mkSecureHelper i id sm

prop_mkSecureHelper :: Positive Int -> ByteString -> Bool
prop_mkSecureHelper (Positive i) bs =
  isJust (mkSecureHelper i id (SM.fromByteString bs)) == (i == B.length bs)

tests :: TestTree
tests = $(testGroupGenerator)
