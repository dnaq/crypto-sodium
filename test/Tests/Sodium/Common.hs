{-# OPTIONS_GHC -fno-warn-orphans #-}
module Tests.Sodium.Common where

import           Control.Applicative
import           Data.Attoparsec.ByteString as AP
import           Data.Bits
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as B
import           Data.Word
import           Test.Tasty.QuickCheck

instance Arbitrary ByteString where
    arbitrary = B.pack <$> arbitrary

tamperAt :: Int -> Word8 -> ByteString -> ByteString
tamperAt i x bs
    | B.null bs = bs
    | otherwise =
        let i' = i `mod` B.length bs
            (f, r) = B.splitAt i' bs
        in B.concat [f, B.singleton (B.head r `xor` x), B.tail r]

isHexDigit :: Word8 -> Bool
isHexDigit w = (w >= 48 && w <= 57) ||
               (w >= 97 && w <= 102) ||
               (w >= 65 && w <= 70)

hexByte :: Parser Word8
hexByte = do h <- hexValue <$> AP.satisfy isHexDigit
             l <- hexValue <$> AP.satisfy isHexDigit
             return $ (h `shiftL` 4) .|. l

hexValue :: Word8 -> Word8
hexValue w | w >= 48 && w <= 57 = w - 48
           | w >= 97 = w - 87
           | otherwise = w - 55

hexBs :: Parser ByteString
hexBs = B.pack <$> many hexByte
