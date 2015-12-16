{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE TemplateHaskell #-}
module Tests.Sodium.Scalarmult.Curve25519 where

import           Crypto.Sodium.Scalarmult.Curve25519
import           Crypto.Sodium.SecureMem

import qualified Data.ByteString                     as B
import           Data.Maybe
import           Data.Word
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck
import           Test.Tasty.TH

instance Arbitrary Scalar where
  arbitrary = mkScalar' <$> vector scalarBytes

instance Arbitrary GroupElement where
  arbitrary = mkGroupElement' <$> vector groupElementBytes

mkScalar' :: [Word8] -> Scalar
mkScalar' = fromJust . mkScalar . fromByteString . B.pack

mkGroupElement' :: [Word8] -> GroupElement
mkGroupElement' = fromJust . mkGroupElement . fromByteString . B.pack

prop_mkScalar :: Scalar -> Bool
prop_mkScalar s = s == fromJust (mkScalar $ unScalar s)

prop_mkGroupElement :: GroupElement -> Bool
prop_mkGroupElement g = g == fromJust (mkGroupElement $ unGroupElement g)

testVectorBase :: [Word8] -> [Word8] -> Assertion
testVectorBase sk pkExpected =
  mkGroupElement' pkExpected @=? scalarmultBase (mkScalar' sk)

prop_diffie_hellman :: Scalar -> Scalar -> Bool
prop_diffie_hellman sk1 sk2 =
  let pk1 = scalarmultBase sk1
      pk2 = scalarmultBase sk2
      k1 = scalarmult sk1 pk2
      k2 = scalarmult sk2 pk1
  in k1 == k2

-- corresponding to tests/scalarmult.c and tests/scalarmult3.cpp from NaCl
case_test_vector_1 :: Assertion
case_test_vector_1 = testVectorBase
                     [ 0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d
                     , 0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45
                     , 0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a
                     , 0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
                     ]
                     [ 0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54
                     , 0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a
                     , 0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4
                     , 0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
                     ]

-- corresponding to tests/scalarmult2.c and tests/scalarmult4.cpp from NaCl
case_test_vector_2 :: Assertion
case_test_vector_2 = testVectorBase
                     [ 0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b
                     , 0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6
                     , 0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd
                     , 0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb
                     ]
                     [ 0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4
                     , 0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37
                     , 0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d
                     , 0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
                     ]

testVector :: [Word8] -> [Word8] -> [Word8] -> Assertion
testVector sk pk kExpected =
  let sk' = mkScalar' sk
      pk' = mkGroupElement' pk
      kExpected' = mkGroupElement' kExpected
  in kExpected' @=? scalarmult sk' pk'

-- corresponding to tests/scalarmult5.c and tests/scalarmult7.cpp from NaCl
case_test_vector_3 :: Assertion
case_test_vector_3 = testVector
                     [ 0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d
                     , 0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45
                     , 0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a
                     , 0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
                     ]
                     [ 0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4
                     , 0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37
                     , 0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d
                     , 0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
                     ]
                     [ 0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1
                     , 0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25
                     , 0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33
                     , 0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
                     ]

-- corresponding to tests/scalarmult6.c from NaCl
case_test_vector_4 :: Assertion
case_test_vector_4 = testVector
                     [ 0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b
                     , 0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6
                     , 0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd
                     , 0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb
                     ]
                     [ 0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54
                     , 0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a
                     , 0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4
                     , 0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
                     ]
                     [ 0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1
                     , 0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25
                     , 0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33
                     , 0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
                     ]

tests :: TestTree
tests = $(testGroupGenerator)