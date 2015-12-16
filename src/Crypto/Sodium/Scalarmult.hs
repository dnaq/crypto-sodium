{- |
= Scalar multiplication

== Representation of group elements
The correspondence between strings and group elements depends on the primitive
implemented by 'scalarmult'. The correspondence is not necessarily
injective in either direction, but it is compatible with scalar multiplication
in the group. The correspondence does not necessarily include all group
elements, but it does include all strings; i.e., every string represents at
least one group element.

== Representation of integers
The correspondence between strings and integers also depends on the primitive
implemented by 'scalarmult'. Every string represents at least one integer.

== Security model
'scalarmult' is designed to be strong as a component of various well-known
"hashed Diffie–Hellman" applications. In particular, it is designed to make the
"computational Diffie–Hellman" problem (CDH) difficult with respect to the
standard base.

'scalarmult' is also designed to make CDH difficult with respect to other
nontrivial bases. In particular, if a represented group element has small
order, then it is annihilated by all represented scalars. This feature allows
protocols to avoid validating membership in the subgroup generated by the
standard base.

NaCl does not make any promises regarding the "decisional Diffie–Hellman"
problem (DDH), the "static Diffie–Hellman" problem (SDH), etc. Users are
responsible for hashing group elements.

== Selected primitive
'scalarmult' is the function 'crypto_scalarmult_curve25519' specified in
<http://nacl.cr.yp.to/valid.html, Cryptography in NaCl>, Sections 2, 3, and 4.
This function is conjectured to be strong. For background see Bernstein,
"Curve25519: new Diffie-Hellman speed records," Lecture Notes in Computer
Science 3958 (2006), 207–228, <http://cr.yp.to/papers.html#curve25519>.
-}
module Crypto.Sodium.Scalarmult
        ( -- * Constants
          scalarBytes -- | Number of bytes in a 'Scalar'.
        , groupElementBytes -- | Number of bytes in a 'GroupElement'.
        , Scalar -- | A 'Scalar', usually some kind of private key.
        , mkScalar -- | Smart constructor for 'Scalar'. Verifies that the length
                   -- of the parameter is 'scalarBytes'.
        , unScalar -- | Returns the contents of a 'Scalar'.

          -- * Types
        , GroupElement -- | A 'GroupElement', usually either a public key
                       -- or a shared secret.
        , mkGroupElement -- | Smart constructor for 'GroupElement'. Verifies that
                         -- the length of the parameter is 'groupElementBytes'.
        , unGroupElement -- | Returns the contents of a 'GroupElement'.

          -- * Scalar Multiplication
        , scalarmult -- | Multiply a 'Scalar' with a 'GroupElement', returning
                     -- a new 'GroupElement'. Usually used for computing a
                     -- shared secret.
        , scalarmultBase -- | Multiply a 'Scalar' with a known base element,
                         -- returning a 'GroupElement'. Usually used for
                         -- computing a public key.
        ) where

import           Crypto.Sodium.Scalarmult.Curve25519
