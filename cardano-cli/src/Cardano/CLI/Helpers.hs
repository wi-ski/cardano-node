{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}

module Cardano.CLI.Helpers
  ( ConversionError(..)
  , HelpersError(..)
  , convertITNverificationKey
  , convertITNsigningKey
  , ensureNewFile
  , ensureNewFileLBS
  , pPrintCBOR
  , readCBOR
  , readText
  , renderConversionError
  , renderHelpersError
  , serialiseSigningKey
  , textToByteString
  , textToLByteString
  , validateCBOR
  ) where

import           Cardano.Prelude

import qualified Codec.Binary.Bech32 as Bech32
import           Codec.CBOR.Pretty (prettyHexEnc)
import           Codec.CBOR.Read (DeserialiseFailure, deserialiseFromBytes)
import           Codec.CBOR.Term (decodeTerm, encodeTerm)
import           Codec.CBOR.Write (toLazyByteString)
import           Control.Exception (IOException)
import qualified Control.Exception as Exception
import           Control.Monad.Trans.Except.Extra (handleIOExceptT, left)
import qualified Data.ByteString.Char8 as SC
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.Text as Text
import           System.Directory (doesPathExist)

import           Cardano.Api (SigningKey(..), StakingVerificationKey(..), textShow)
import           Cardano.Binary (Decoder, fromCBOR)
import qualified Cardano.Chain.Delegation as Delegation
import qualified Cardano.Chain.Update as Update
import           Cardano.Chain.Block (fromCBORABlockOrBoundary)
import qualified Cardano.Chain.UTxO as UTxO
import           Cardano.Config.Protocol (CardanoEra(..))
import           Cardano.Config.Types
import qualified Cardano.Crypto as Crypto
import qualified Cardano.Crypto.DSIGN as DSIGN

import qualified Shelley.Spec.Ledger.Keys as Shelley

data HelpersError
  = CardanoEraNotSupportedFail !CardanoEra
  | CBORPrettyPrintError !DeserialiseFailure
  | CBORDecodingError !DeserialiseFailure
  | IOError' !FilePath !IOException
  | OutputMustNotAlreadyExist FilePath
  | ReadCBORFileFailure !FilePath !Text
  deriving Show

renderHelpersError :: HelpersError -> Text
renderHelpersError err =
  case err of
    CardanoEraNotSupportedFail era -> "Cardano era not supported: " <> (Text.pack $ show era)
    OutputMustNotAlreadyExist fp -> "Output file/directory must not already exist: " <> Text.pack fp
    ReadCBORFileFailure fp err' -> "CBOR read failure at: " <> Text.pack fp <> (Text.pack $ show err')
    CBORPrettyPrintError err' -> "Error with CBOR decoding: " <> (Text.pack $ show err')
    CBORDecodingError err' -> "Error with CBOR decoding: " <> (Text.pack $ show err')
    IOError' fp ioE -> "Error at: " <> (Text.pack fp) <> " Error: " <> (Text.pack $ show ioE)

decodeCBOR
  :: LByteString
  -> (forall s. Decoder s a)
  -> Either HelpersError (LB.ByteString, a)
decodeCBOR bs decoder =
  first CBORDecodingError $ deserialiseFromBytes decoder bs

-- | Checks if a path exists and throws and error if it does.
ensureNewFile :: (FilePath -> a -> IO ()) -> FilePath -> a -> ExceptT HelpersError IO ()
ensureNewFile writer outFile blob = do
  exists <- liftIO $ doesPathExist outFile
  when exists $
    left $ OutputMustNotAlreadyExist outFile
  liftIO $ writer outFile blob

ensureNewFileLBS :: FilePath -> LB.ByteString -> ExceptT HelpersError IO ()
ensureNewFileLBS = ensureNewFile LB.writeFile

serialiseSigningKey
  :: CardanoEra
  -> Crypto.SigningKey
  -> Either HelpersError LB.ByteString
serialiseSigningKey ByronEraLegacy (Crypto.SigningKey k) = pure $ toLazyByteString (Crypto.toCBORXPrv k)
serialiseSigningKey ByronEra (Crypto.SigningKey k) = pure $ toLazyByteString (Crypto.toCBORXPrv k)
serialiseSigningKey ShelleyEra _ = Left $ CardanoEraNotSupportedFail ShelleyEra

textToLByteString :: Text -> LB.ByteString
textToLByteString = LC.pack . Text.unpack

textToByteString :: Text -> SC.ByteString
textToByteString = SC.pack . Text.unpack

pPrintCBOR :: LByteString -> ExceptT HelpersError IO ()
pPrintCBOR bs = do
  case deserialiseFromBytes decodeTerm bs of
    Left err -> left $ CBORPrettyPrintError err
    Right (remaining, decodedVal) -> do
      liftIO . putTextLn . toS . prettyHexEnc $ encodeTerm decodedVal
      unless (LB.null remaining) $
        pPrintCBOR remaining

readCBOR :: FilePath -> ExceptT HelpersError IO LByteString
readCBOR fp =
  handleIOExceptT
    (ReadCBORFileFailure fp . toS . displayException)
    (LB.readFile fp)

validateCBOR :: CBORObject -> LByteString -> Either HelpersError Text
validateCBOR cborObject bs =
  case cborObject of
    CBORBlockByron epochSlots -> do
      (const () ) <$> decodeCBOR bs (fromCBORABlockOrBoundary epochSlots)
      Right "Valid Byron block."

    CBORDelegationCertificateByron -> do
      (const () ) <$> decodeCBOR bs (fromCBOR :: Decoder s Delegation.Certificate)
      Right "Valid Byron delegation certificate."

    CBORTxByron -> do
      (const () ) <$> decodeCBOR bs (fromCBOR :: Decoder s UTxO.Tx)
      Right "Valid Byron Tx."

    CBORUpdateProposalByron -> do
      (const () ) <$> decodeCBOR bs (fromCBOR :: Decoder s Update.Proposal)
      Right "Valid Byron update proposal."

    CBORVoteByron -> do
      (const () ) <$> decodeCBOR bs (fromCBOR :: Decoder s Update.Vote)
      Right "Valid Byron vote."

--------------------------------------------------------------------------------
-- ITN verification/signing key conversion to Haskell verficiation/signing keys
--------------------------------------------------------------------------------

data ConversionError
  = Bech32DecodingError !FilePath !Bech32.DecodingError
  | ITNError !Text
  | SigningKeyDeserializationError !ByteString
  | VerificationKeyDeserializationError !ByteString
  deriving Show

renderConversionError :: ConversionError -> Text
renderConversionError err =
  case err of
    Bech32DecodingError fp decErr ->
      "Error decoding Bech32 key at:" <> textShow fp <> " Error: " <> textShow decErr
    ITNError errMessage -> errMessage
    SigningKeyDeserializationError sKey ->
      "Error deserialising signing key: " <> textShow (SC.unpack sKey)
    VerificationKeyDeserializationError vKey ->
      "Error deserialising verification key: " <> textShow (SC.unpack vKey)

-- | Convert public ed25519 key to a Shelley stake verification key
convertITNverificationKey :: Text -> Either ConversionError StakingVerificationKey
convertITNverificationKey pubKey = do
  keyBS <- decodeBech32Key pubKey
  case DSIGN.rawDeserialiseVerKeyDSIGN keyBS of
    Just verKey -> Right . StakingVerificationKeyShelley $ Shelley.VKey verKey
    Nothing -> Left $ VerificationKeyDeserializationError keyBS

-- | Convert private ed22519 key to a Shelley signing key.
convertITNsigningKey :: Text -> Either ConversionError SigningKey
convertITNsigningKey privKey = do
  keyBS <- decodeBech32Key privKey
  case DSIGN.rawDeserialiseSignKeyDSIGN keyBS of
    Just signKey -> Right $ SigningKeyShelley signKey
    Nothing -> Left $ SigningKeyDeserializationError keyBS

-- | Convert ITN Bech32 public or private keys to 'ByteString's
decodeBech32Key :: Text -> Either ConversionError ByteString
decodeBech32Key key =
  case Bech32.decode key of
    Left err -> Left . ITNError $ textShow err
    Right (_, dataPart) -> case Bech32.dataPartToBytes dataPart of
                             Nothing -> Left $ ITNError "Error extracting a ByteString from a DataPart: \
                                                      \See bech32 library function: dataPartToBytes"
                             Just bs -> Right bs

readText :: FilePath -> IO (Either Text Text)
readText fp = do
  eStr <- Exception.try $ readFile fp
  case eStr of
    Left e -> return . Left $ handler e
    Right txt -> return $ Right txt
 where
  handler :: IOException -> Text
  handler e = Text.pack $ "Cardano.Api.Convert.readText: "
                     ++ displayException e
