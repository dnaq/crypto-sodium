{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE RecordWildCards      #-}
{-# LANGUAGE TypeSynonymInstances #-}
module Tests.Sodium.Stream.Salsa208 where

import           Tests.Sodium.Stream.Common

import           Crypto.Sodium.Stream.Salsa208

import           Test.Tasty

tests :: TestTree
tests = testGroup "Tests.Sodium.Stream.Salsa208" $
        mkTests salsa208
