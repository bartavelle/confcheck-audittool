{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TupleSections #-}
module AuditTool
    ( parseAuditTool
    ) where

import qualified Data.ByteString.Lazy as BSL
import qualified Data.HashMap.Lazy as HM
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.ByteString.Base16 as B16
import qualified Data.Textual as TX

import Control.Applicative
import Control.Monad
import Control.Monad.Writer.Strict
import Control.Lens hiding (children)
import Text.XML.Expat.Lens
import Text.XML.Expat.Tree (NodeG(..), Attributes)
import Data.Thyme
import Data.Maybe

import Analyzis.Types
import Analyzis.Common
import Analyzis.Windows.ACE

import qualified Data.Parsers.FastText as PF
import qualified Text.Parser.Char as P

type Node = NodeG [] Text Text
type KV = HM.HashMap Text Text

attr :: Text -> Traversal' (Attributes Text Text) Text
attr t = traverse . filtered ( (== t) . fst ) . _2

mkKV :: Node -> KV
mkKV = HM.fromList . map toEntry . view children
    where
        toEntry n = (n ^. name, n ^. plate . text)

childnamed :: Text -> Traversal' Node Node
childnamed t = children . traverse . named t

toNodeMap :: Fold Node (HM.HashMap Text Node)
toNodeMap = children . to mkNodeMap

mkNodeMap :: [Node] -> HM.HashMap Text Node
mkNodeMap = HM.fromList . map (\n -> (n ^. name, n))

utctime :: PF.Parser UTCTime
utctime = do
    d <- PF.parseYMD
    void (PF.char ' ')
    difftime <- PF.parseDTime
    return (UTCTime d difftime ^. from utcTime)

adInfo :: KV -> Writer [ConfigInfo] ()
adInfo n = do
    mapM_ (stell . AuditStart) (n ^? ix "start_date" . PF.pFold utctime)
    mapM_ (stell . AuditEnd) (n ^? ix "end_date" . PF.pFold utctime)
    mapM_ (\v -> stell (MiscInfo ("Audit_tool version " <> v))) (n ^? ix "version")

mkError :: Alternative m => Either Text (m a) -> Writer [ConfigInfo] (m a)
mkError e = case e of
                Left rr -> tell [ConfigError (MiscError rr)] >> return empty
                Right x -> return x

stell :: a -> Writer [a] ()
stell = tell . (:[])

serror :: Text -> Writer [ConfigInfo] ()
serror = stell . ConfigError . MiscError

xmlerror :: Text -> Node -> Writer [ConfigInfo] ()
xmlerror desc n = serror (desc <> T.decodeUtf8 (review _XML n))

adSystem :: HM.HashMap Text Node -> Writer [ConfigInfo] ()
adSystem n = do
    let ptag t = n ^? ix t ./ text
    constr <- mkError $ case n ^? ix "type" ./ text of
                  Just "Client" -> Right (Just WindowsClient)
                  Just "Server" -> Right (Just WindowsServer)
                  Just what -> Left ("Unknown windows os type: " <> what)
                  Nothing -> Right Nothing
    let v = n ^.. ix "kernel_version" . plate . text . to (T.splitOn ".") . folded . PF.pFold PF.decimal
    mapM_ stell $ do
        c <- constr
        ostype <- ptag "os_type"
        return (UVersion (UnixVersion (c ostype) v))
    mapM_ (stell . Hostname) (ptag "computer_dnsdomain_name" <|> ptag "computer_dnsdomain_name")
    mapM_ (\sid -> stell (MiscInfo ("Computer GUID: " <> sid))) (ptag "computer_guid")
    mapM_ (\sid -> stell (MiscInfo ("Computer SID: " <> sid))) (ptag "computer_sid")

adHives :: Node -> Writer [ConfigInfo] (Maybe (Text, RegistryHive))
adHives n = do
    let attrs = n ^. attributes
        decodeSid t = case t ^? _SID of
                          Nothing -> HiveNamed t
                          Just sid -> HiveSID sid
    case (,) <$> attrs ^? attr "id_hive" <*> attrs ^? attr "user" of
        Nothing -> Nothing <$ xmlerror "Invalid hive: " n
        o -> return (fmap (fmap decodeSid) o)

mkValue :: Attributes Text Text -> Writer [ConfigInfo] (Maybe (Text, RegistryValue))
mkValue attrs = do
    let o = (,) <$> (attrs ^? attr "name") <*> ( (,) <$> (attrs ^? attr "type") <*> (attrs ^? attr "data") >>= uncurry decodeKey )
        decodeKey tp dt = case tp of
                              "REG_DWORD" -> RVDWord <$> text2Int dt
                              "REG_SZ" -> return (RVSZ dt)
                              "REG_MULTI_SZ" -> return (RVMultiSZ dt)
                              "REG_EXPAND_SZ" -> return (RVExpand dt)
                              "REG_BINARY" -> case B16.decode (T.encodeUtf8 dt) of
                                                  (binary, "") -> return (RVBinary binary)
                                                  _ -> Nothing
                              _ -> Nothing
    when (isNothing o) (xmlerror "Invalid registry value: " (Element "value" attrs []))
    return o

adRegistry :: HM.HashMap Int SecurityDescriptor -> HM.HashMap Text RegistryHive -> Node -> Writer [ConfigInfo] ()
adRegistry sdmap hives n = do
    let attrs = n ^. attributes
        rk = RegistryKey <$> (attrs ^? attr "id_hive" >>= flip HM.lookup hives)
                         <*> (attrs ^? attr "name")
                         <*> (attrs ^? attr "last_write" . PF.pFold utctime)
                         <*> (attrs ^? attr "id_sd_key" >>= text2Int >>= flip HM.lookup sdmap)
    case rk of
        Nothing -> xmlerror "Invalid hive key: " n
        Just k -> (WinRegistry . k . HM.fromList . catMaybes <$> mapM mkValue (n ^.. childnamed "value" . attributes)) >>= stell

adUser :: SID -> Node -> Writer [ConfigInfo] (Maybe SID)
adUser computersid n = do
    let kv = mkKV n
        msid = fmap (resolveRSID computersid . DomainRelative) (kv ^? ix "user_id" >>= text2Integral)
        muserinfo = do
            nm <- kv ^? ix "name"
            let cm = kv ^? ix "comment"
            flags <- fmap decodeUACFlags (kv ^? ix "flags" >>= text2Int)
            sid <- msid
            return (WinUser nm sid flags cm)
        mlogininfo = WinLogonInfo <$> msid
                                  <*> (kv ^? ix "num_logons" >>= text2Int)
                                  <*> (kv ^? ix "password_age" >>= text2Int)
                                  <*> (kv ^? ix "usri2_last_logon" . PF.pFold utctime)
    case muserinfo of
        Nothing -> xmlerror "Bas user:" n
        Just userinfo -> stell (ConfWinUser userinfo)
    forM_ mlogininfo $ \li -> when (_wliNumLogon li > 0) (stell (ConfWinLoginfo li))
    return (fmap _winsid muserinfo)

adGroup :: Node -> Writer [ConfigInfo] (Maybe WinGroup)
adGroup n = do
    let kv = mkKV n
    case WinGroup <$> (kv ^? ix "name") <*> (kv ^? ix "sid" . _SID) <*> pure (kv ^? ix "comment") of
        Nothing -> Nothing <$ xmlerror "Bad group: " n
        Just g -> do
            members <- forM (n ^.. childnamed "members" . childnamed "member") $ \mnode -> do
                let mgroupinfo = (,) <$> mn ^? ix "domainandname" <*> mn ^? ix "sid" . _SID
                    mn = mkKV mnode
                when (isNothing mgroupinfo) (xmlerror "Bad group member in: " mnode)
                return mgroupinfo
            let grp = g (catMaybes members)
            stell (ConfWinGroup grp)
            return (Just grp)

mkSidInfo :: Node -> Writer [ConfigInfo] (Maybe (SID, Maybe (Text, Text)))
mkSidInfo n = do
    let attrs = n ^. attributes
        mval = do
            s <- attrs ^? attr "sid" . _SID
            let du = (,) <$> attrs ^? attr "domain"
                         <*> attrs ^? attr "user"
            return (s, du)
    when (isNothing mval) (xmlerror "Invalid sid value: " n)
    return mval

mkSd :: Node -> Writer [ConfigInfo] (Maybe (Int, SecurityDescriptor))
mkSd n = do
    let n' = mkKV n
        sd = do
            idSd    <- n' ^? ix "id_sd" >>= text2Int
            typeRaw <- n' ^? ix "type"
            let g = n' ^? ix "G" >>= TX.fromText . T.drop 2
                o = n' ^? ix "O" >>= TX.fromText . T.drop 2
            sdt     <- case typeRaw of
                           "REGISTRY"     -> Just SDRegistry
                           "APPID_ACCESS" -> Just SDAppidAccess
                           "APPID_LAUNCH" -> Just SDAppidLaunch
                           "SERVICE"      -> Just SDService
                           "FILE"         -> Just SDFile
                           "PIPE"         -> Just SDPipe
                           "PROCESS"      -> Just SDProcess
                           "TASKv2"       -> Just SDTaskV2
                           "SCM"          -> Just SDSCM
                           _              -> Nothing
            dacl    <- n' ^? ix "D" . PF.pFold (P.text "D:" >> TX.textual)
            rsacl   <- n' ^? ix "S"
            sacl    <- if T.null rsacl
                           then pure nullACL
                           else rsacl ^? PF.pFold (P.text "S:" >> TX.textual)
            return (idSd, SecurityDescriptor sdt o g dacl sacl)
    when (isNothing sd) $ do
        xmlerror "Bad SD: " n
    return sd

extractFromReport :: [Node] -> [ConfigInfo]
extractFromReport n = execWriter $ do
    let n' = mkNodeMap n
    forM_ (n' ^? ix "audittool_infos") (adInfo . mkKV)
    sidMap <- HM.fromList . catMaybes <$> mapM mkSidInfo (n' ^.. ix "sid_base" . childnamed "value")
    sdMap <- HM.fromList . catMaybes <$> mapM mkSd (n' ^.. ix "sd_base" . childnamed "sd")
    forM_ (n' ^? ix "system" . toNodeMap) adSystem
    hivemap <- HM.fromList . catMaybes <$> forM (n' ^.. ix "hives" ./ named "hive") adHives
    forM_ (n' ^.. ix "registry_generic_keys" ./ named "key") (adRegistry sdMap hivemap)
    forM_ (n' ^.. ix "groups" ./ named "group") adGroup
    forM_ (n' ^? ix "system" ./ named "computer_sid" ./ text . _SID) $ \csid ->
        forM_ (n' ^.. ix "users" ./ named "user") (adUser csid)

parseAuditTool :: BSL.ByteString -> [ConfigInfo]
parseAuditTool d = case d ^? strict . _XML . named "audit_tool" . children of
                       Nothing -> undefined
                       Just p -> extractFromReport p
