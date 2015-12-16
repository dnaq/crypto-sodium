{- |
= Hashing

== Security model
The 'hash' function is designed to be usable as a strong
component of DSA, RSA-PSS, key derivation, hash-based
message-authentication codes, hash-based ciphers, and various other
common applications.  Strong means that the security of these
applications, when instantiated with 'hash', is the same
as the security of the applications against generic attacks. In
particular, the 'hash' function is designed to make
finding collisions difficult.

== Selected primitive
'hash' is currently an implementation of 'SHA-512'.

There has been considerable degradation of public confidence in the
security conjectures for many hash functions, including 'SHA-512'.
However, for the moment, there do not appear to be alternatives that
inspire satisfactory levels of confidence. One can hope that NIST's
SHA-3 competition will improve the situation.

== Alternate primitives
NaCl supports the following hash functions:

> ------------------------------------
> |crypto_hash       |primitive|BYTES|
> |------------------|---------|-----|
> |crypto_hash_sha256|SHA-256  |32   |
> |crypto_hash_sha512|SHA-512  |64   |
> ------------------------------------

== Example
>>> :set -XOverloadedStrings
>>> hash "some_data"
Digest {unDigest = "\225d^t\146\240\&2\251b\198t\219uP\v\231\178`\191\192\218\169e\130\GS\219?\138I\181\211\&7\136\238?\EOTgD\226\185Z\251\\=\143%\NUL\197I\202\137\215\159\198\137\b\133\210\142\ENQP\aBO"}
-}
module Crypto.Sodium.Hash
       ( -- * Constants
         digestBytes -- | Number of bytes in a 'Digest'.

         -- * Types
       , Digest -- | Digest structure.
       , unDigest -- | Returns the contents of a 'Digest'.
       , mkDigest -- | Smart constructor for 'Digest'. Verifies that the length
                  -- of the parameter is 'digestBytes'.

         -- * Hashing
       , hash -- | Hashes a message.
       ) where

import           Crypto.Sodium.Hash.Sha512
