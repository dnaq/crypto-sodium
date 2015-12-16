{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}
import           Crypto.Sodium                               (withSodiumDo)

import           Tests.Sodium.Auth.HmacSha256                as HmacSha256
import           Tests.Sodium.Auth.HmacSha512                as HmacSha512
import           Tests.Sodium.Auth.HmacSha512256             as HmacSha512256
import           Tests.Sodium.Box.Curve25519Xsalsa20Poly1305 as Curve25519Xsalsa20Poly1305
import           Tests.Sodium.Hash.Sha256                    as Sha256
import           Tests.Sodium.Hash.Sha512                    as Sha512
import           Tests.Sodium.Internal                       as Internal
import           Tests.Sodium.OnetimeAuth.Poly1305           as Poly1305
import           Tests.Sodium.Scalarmult.Curve25519          as Curve25519
import           Tests.Sodium.SecretBox.Xsalsa20Poly1305     as Xsalsa20Poly1305
import           Tests.Sodium.SecureMem                      as SecureMem
import           Tests.Sodium.Sign.Ed25519                   as Ed25519
import           Tests.Sodium.Stream.Aes128Ctr               as Aes128Ctr
import           Tests.Sodium.Stream.Chacha20                as Chacha20
import           Tests.Sodium.Stream.Salsa20                 as Salsa20
import           Tests.Sodium.Stream.Salsa2012               as Salsa2012
import           Tests.Sodium.Stream.Salsa208                as Salsa208
import           Tests.Sodium.Stream.Xsalsa20                as Xsalsa20

import           Test.Tasty
import           Test.Tasty.TH

test_Modules :: [TestTree]
test_Modules = [ Curve25519Xsalsa20Poly1305.tests
               , Xsalsa20Poly1305.tests
               , HmacSha256.tests
               , HmacSha512.tests
               , HmacSha512256.tests
               , Poly1305.tests
               , Curve25519.tests
               , Sha256.tests
               , Sha512.tests
               , Internal.tests
               , Ed25519.tests
               , Aes128Ctr.tests
               , Chacha20.tests
               , Salsa2012.tests
               , Salsa208.tests
               , Salsa20.tests
               , Xsalsa20.tests
               , SecureMem.tests
               ]

main :: IO ()
main = withSodiumDo $(defaultMainGenerator)
