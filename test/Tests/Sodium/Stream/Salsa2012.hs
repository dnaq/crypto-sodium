{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE RecordWildCards      #-}
{-# LANGUAGE TypeSynonymInstances #-}
module Tests.Sodium.Stream.Salsa2012 where

import           Tests.Sodium.Stream.Common

import           Crypto.Sodium.Stream.Salsa2012

import           Test.Tasty

tests :: TestTree
tests = testGroup "Tests.Sodium.Stream.Salsa2012" $
        mkTests salsa2012
