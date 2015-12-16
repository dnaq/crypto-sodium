{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Tests.Sodium.Stream.Common where

import           Tests.Sodium.Common           ()

import           Crypto.Sodium.SecureMem
import           Crypto.Sodium.Stream.Internal

import           Data.Bits
import qualified Data.ByteString               as B
import           Data.Maybe
import           Test.QuickCheck.Monadic       as QM
import           Test.Tasty
import           Test.Tasty.QuickCheck

mkTests :: forall t. StreamCipher t
        -> [TestTree]
mkTests StreamCipher {..} =
  [
    testProperty "encrypt decrypt" prop_EncryptDecrypt
  , testProperty "stream xor" prop_StreamXor
  , testProperty "mkKey" prop_mkKey
  , testProperty "mkNonce" prop_mkNonce
  , testProperty "randomKey" prop_randomKey
  ]
  where
    arbitraryKey :: Gen (Key t)
    arbitraryKey = fromJust . mkKey . fromByteString . B.pack <$>
                   vector keyBytes

    arbitraryNonce :: Gen (Nonce t)
    arbitraryNonce = fromJust . mkNonce . B.pack <$> vector nonceBytes

    prop_EncryptDecrypt m =
        forAll arbitraryKey $ \k ->
        forAll arbitraryNonce $ \n ->
        m == streamXor k n (streamXor k n m)

    prop_StreamXor m =
        forAll arbitraryKey $ \k ->
        forAll arbitraryNonce $ \n ->
        streamXor k n m == B.pack (B.zipWith xor m $
                                   stream k n $
                                   B.length m)
    prop_mkKey = forAll arbitraryKey $ \k -> k == fromJust (mkKey $ unKey k)
    prop_mkNonce = forAll arbitraryNonce $ \n -> n == fromJust (mkNonce $ unNonce n)
    prop_randomKey = monadicIO $ do
        k <- run randomKey
        n <- pick arbitraryNonce
        m <- pick arbitrary
        QM.assert $ m == streamXor k n (streamXor k n m)
