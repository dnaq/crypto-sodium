{- |
= Sodium library initialization functions.
-}
module Crypto.Sodium
       ( withSodiumDo
       ) where

import           Control.Exception (evaluate)
import           Control.Monad     (when, unless)
import           Foreign.C.Types   (CInt (..))

foreign import ccall unsafe "sodium.h sodium_init"
  c_sodium_init :: IO CInt

-- | Initializes the Sodium library and should be used before any other
-- function provided by Sodium. The function can be called more than once,
-- but it should not be executed by multiple threads simultaneously.
-- The recommended way to use 'withSodiumDo' is:
--
-- > main = withSodiumDo $ do {..}
withSodiumDo :: IO a -> IO a
withSodiumDo x = do
  r <- c_sodium_init
  when (r == -1) $ evaluate $ error "withSodiumDo: failed to initalize sodium"
  x
