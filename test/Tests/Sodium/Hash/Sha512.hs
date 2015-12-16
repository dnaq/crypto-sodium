{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}
module Tests.Sodium.Hash.Sha512 where

import           Tests.Sodium.Hash.Common

import           Crypto.Sodium.Hash.Sha512

import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.TH

case_digestBytes :: Assertion
case_digestBytes = 64 @=? digestBytes

case_test_vector_1 :: Assertion
case_test_vector_1 = testVector sha512
                     -- corresponding to tests/hash.c, tests/hash2.cpp,
                     -- tests/hash3.c and tests/hash4.cpp from NaCl
                     [ 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0xa ]
                     [ 0x24, 0xf9, 0x50, 0xaa, 0xc7, 0xb9, 0xea, 0x9b
                     ,0x3c, 0xb7, 0x28, 0x22, 0x8a, 0x0c, 0x82, 0xb6
                     ,0x7c, 0x39, 0xe9, 0x6b, 0x4b, 0x34, 0x47, 0x98
                     ,0x87, 0x0d, 0x5d, 0xae, 0xe9, 0x3e, 0x3a, 0xe5
                     ,0x93, 0x1b, 0xaa, 0xe8, 0xc7, 0xca, 0xcf, 0xea
                     ,0x4b, 0x62, 0x94, 0x52, 0xc3, 0x80, 0x26, 0xa8
                     ,0x1d, 0x13, 0x8b, 0xc7, 0xaa, 0xd1, 0xaf, 0x3e
                     ,0xf7, 0xbf, 0xd5, 0xec, 0x64, 0x6d, 0x6c, 0x28]


case_SHA512ShortMsg :: Assertion
case_SHA512ShortMsg = testNistVectors sha512
                      "test/testvectors/SHA512ShortMsg.rsp"

case_SHA512LongMsg :: Assertion
case_SHA512LongMsg = testNistVectors sha512
                     "test/testvectors/SHA512LongMsg.rsp"

tests :: TestTree
tests = $(testGroupGenerator)
