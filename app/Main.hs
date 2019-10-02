module Main where

import qualified Data.ByteString.Lazy as BSL

import           AuditTool

main :: IO ()
main = BSL.readFile "sample/DESKTOP-M00LTUT.xml" >>= mapM_ print . parseAuditTool
