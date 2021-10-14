module Main where

import AuditTool
import qualified Data.ByteString.Lazy as BSL

main :: IO ()
main = BSL.readFile "sample/DESKTOP-M00LTUT.xml" >>= mapM_ print . parseAuditTool
