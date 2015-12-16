{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE RecordWildCards      #-}
{-# LANGUAGE TypeSynonymInstances #-}
module Tests.Sodium.Stream.Aes128Ctr where

import           Tests.Sodium.Stream.Common

import           Crypto.Sodium.Stream.Aes128Ctr

import           Test.Tasty

tests :: TestTree
tests = testGroup "Tests.Sodium.Stream.Aes128Ctr" $
        mkTests aes128Ctr
