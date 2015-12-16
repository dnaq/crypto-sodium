{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE TemplateHaskell #-}
module Tests.Sodium.SecureMem where

import           Tests.Sodium.Common     ()

import           Crypto.Sodium.SecureMem as SM

import           Control.Exception
import           Control.Monad
import           Data.ByteString         (ByteString)
import qualified Data.ByteString         as B
import           Data.Word
import           Foreign.Ptr
import           Foreign.Storable
import           System.IO.Unsafe
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck
import           Test.Tasty.TH

instance Arbitrary SecureMem where
  arbitrary = fromByteString <$> arbitrary

prop_fromToByteString :: ByteString -> Bool
prop_fromToByteString bs = bs == toByteString (fromByteString bs)

prop_eq :: ByteString -> ByteString -> Bool
prop_eq bs1 bs2 = (bs1 == bs2) == (fromByteString bs1 == fromByteString bs2)

prop_eq2 :: SecureMem -> SecureMem -> Bool
prop_eq2 sm1 sm2 = (sm1 == sm2) == (toByteString sm1 == toByteString sm2)

prop_eq_same_length :: NonNegative Int -> Property
prop_eq_same_length (NonNegative i) =
  forAll (B.pack <$> vector i) $ \bs1 ->
  forAll (B.pack <$> vector i) $ \bs2 ->
  prop_eq bs1 bs2

prop_createAndFill' :: NonNegative Int -> Word8 -> Bool
prop_createAndFill' (NonNegative i) w =
  fromByteString (B.replicate i w) == sm && r == SM.length sm
  where
    (sm, r) = unsafeDupablePerformIO $ create' i $ loop 0
    loop i' p | i == i' = return i'
              | otherwise = do poke p w; loop (i' + 1) (p `plusPtr` 1)

empty :: SecureMem
empty = fromByteString B.empty

case_createEmpty :: Assertion
case_createEmpty = do
  x <- create 0 (const $ return ())
  empty @=? x

assertException :: (Exception e, Eq e) => e -> IO a -> IO ()
assertException ex act =
  handleJust isWanted (const $ return ()) $ do
    void act
    assertFailure $ "Expected exception: " ++ show ex
  where
    isWanted = guard . (==ex)

case_createNegative :: Assertion
case_createNegative =
  assertException (ErrorCall "mallocForeignPtrBytes: size must be >= 0") $
  create (-1) (const $ return ())

tests :: TestTree
tests = $(testGroupGenerator)
