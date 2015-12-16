{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE RecordWildCards      #-}
{-# LANGUAGE TypeSynonymInstances #-}
module Tests.Sodium.Stream.Salsa20 where

import           Tests.Sodium.Stream.Common

import           Crypto.Sodium.Hash.Sha256
import           Crypto.Sodium.SecureMem
import           Crypto.Sodium.Stream.Salsa20

import qualified Data.ByteString              as B
import           Data.Maybe
import           Test.Tasty
import           Test.Tasty.HUnit

tests :: TestTree
tests = testGroup "Tests.Sodium.Stream.Salsa20" $
        testVector :
        mkTests salsa20

testVector :: TestTree -- corresponding to tests/stream2.c
                       -- and test/stream6.cpp from NaCl
testVector = testCase "vector" $ do
  let secondkey = fromJust . mkKey . fromByteString . B.pack $
                  [ 0xdc,0x90,0x8d,0xda,0x0b,0x93,0x44,0xa9
                  , 0x53,0x62,0x9b,0x73,0x38,0x20,0x77,0x88
                  , 0x80,0xf3,0xce,0xb4,0x21,0xbb,0x61,0xb9
                  , 0x1c,0xbd,0x4c,0x3e,0x66,0x25,0x6c,0xe4]
      noncesuffix = fromJust . mkNonce . B.pack $
                    [0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37]
      output = stream secondkey noncesuffix 4194304
      digest = fromJust . mkDigest . B.pack $
               [0x66, 0x2b, 0x9d, 0x0e, 0x34, 0x63, 0x02, 0x91
               , 0x56, 0x06, 0x9b, 0x12, 0xf9, 0x18, 0x69, 0x1a
               , 0x98, 0xf7, 0xdf, 0xb2, 0xca, 0x03, 0x93, 0xc9
               , 0x6b, 0xbf, 0xc6, 0xb1, 0xfb, 0xd6, 0x30, 0xa2]
  digest @=? hash output
