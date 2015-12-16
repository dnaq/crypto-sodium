{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}
module Tests.Sodium.Hash.Sha256 where

import           Tests.Sodium.Hash.Common

import           Crypto.Sodium.Hash.Sha256

import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.TH

case_digestBytes :: Assertion
case_digestBytes = 32 @=? digestBytes

case_test_vector_1 :: Assertion
case_test_vector_1 = testVector sha256 []
                     [ 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14
                     , 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24
                     , 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c
                     , 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
                     ]

case_test_vector_2 :: Assertion
case_test_vector_2 = testVector sha256
                     [ 0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63
                     , 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20
                     , 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70
                     , 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74
                     , 0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20
                     , 0x64, 0x6f, 0x67
                     ]
                     [ 0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94
                     , 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f
                     , 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76
                     , 0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92
                     ]

case_SHA256ShortMsg :: Assertion
case_SHA256ShortMsg = testNistVectors sha256
                      "test/testvectors/SHA256ShortMsg.rsp"

case_SHA256LongMsg :: Assertion
case_SHA256LongMsg = testNistVectors sha256
                     "test/testvectors/SHA256LongMsg.rsp"

tests :: TestTree
tests = $(testGroupGenerator)