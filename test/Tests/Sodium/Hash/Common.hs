{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Tests.Sodium.Hash.Common where

import           Tests.Sodium.Common

import           Crypto.Sodium.Hash.Internal

import           Control.Applicative
import           Control.Monad
import           Data.Attoparsec.ByteString       as AP
import           Data.Attoparsec.ByteString.Char8 as A8
import           Data.ByteString                  (ByteString)
import qualified Data.ByteString                  as B
import           Data.Word

import           Test.Tasty.HUnit

testVector :: Hash h -> [Word8] -> [Word8] -> Assertion
testVector Hash {..} x hexp =
  let x' = B.pack x
      hexp' = B.pack hexp
      h = hash x'
  in
      hexp' @=? unDigest h

data TestVector = TestVector { tvLen :: !Int
                             , tvMsg :: !ByteString
                             , tvMd  :: !ByteString
                             } deriving Show

entry :: Parser TestVector
entry = do
  l <- string "Len = " *> decimal <* char '\n'
  msg <- string "Msg = " *> hexBs <* char '\n'
  md <- string "MD = " *> hexBs <* char '\n'
  return $ TestVector l (B.take l msg) md

vectorFile :: Parser [TestVector]
vectorFile = many comment *>
             char '\n' *>
             string "[L = " *> A8.takeWhile isDigit *> string "]\n\n" *>
             sepBy1 entry (char '\n')

comment :: Parser ()
comment = char '#' *> A8.takeWhile (/='\n') *> char '\n' *> pure ()

testNistVectors :: Hash h -> FilePath -> Assertion
testNistVectors Hash {..} filename = do
  Right entries <- parseOnly vectorFile <$> B.readFile filename
  forM_ entries $ \e -> do
    let h = unDigest $ hash $ tvMsg e
    tvMd e @=? h
