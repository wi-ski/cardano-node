module Cardano.CLI.Shelley.Run.StakeAddress
  ( ShelleyStakeAddressCmdError
  , checkKeyPair
  , renderShelleyStakeAddressCmdError
  , runStakeAddressCmd
  ) where

import           Cardano.Prelude

import qualified Data.ByteString.Lazy.Char8 as LBS
import qualified Data.Text.IO as Text

import           Control.Monad.Trans.Except (ExceptT)
import           Control.Monad.Trans.Except.Extra (firstExceptT, hoistEither, left, newExceptT)

import           Cardano.Api

import           Cardano.Api (StakingVerificationKey (..),
                   readStakingVerificationKey,
                   shelleyDeregisterStakingAddress, shelleyDelegateStake,
                   shelleyRegisterStakingAddress, writeCertificate)
import           Shelley.Spec.Ledger.Keys (VKey(..), hashKey)
import           Cardano.Config.Shelley.ColdKeys hiding (writeSigningKey)
import qualified Cardano.Crypto.DSIGN as DSIGN


import           Cardano.CLI.Helpers
import           Cardano.CLI.Shelley.Parsers

data ShelleyStakeAddressCmdError
  = ShelleyStakeReadPoolOperatorKeyError !FilePath !KeyError
  | ShelleyStakeAddressConvError !ConversionError
  | ShelleyStakeAddressKeyPairError
      !Text
      -- ^ bech32 private key
      !Text
      -- ^ bech32 public key
  | ShelleyStakeAddressReadFileError !FilePath !Text
  | ShelleyStakeAddressReadVerKeyError !FilePath !ApiError
  | ShelleyStakeAddressUnequalKeysError
      !Int
      -- ^ Number of verification keys
      !Int
      -- ^ Number of signing keys
  | ShelleyStakeAddressUnequalNumberOfOutputFilesError
      !Int
      -- ^ Number of output files
      !Int
      -- ^ Number of signing keys
  | ShelleyStakeAddressLessKeysThanOutsError
      !Int
      -- ^ Number of input keys
      !Int
      -- ^ Number of output file paths
  | ShelleyStakeAddressMoreKeysThanOutsError
      !Int
      -- ^ Number of input keys
      !Int
      -- ^ Number of output file paths
  | ShelleyStakeAddressWriteCertError !FilePath !ApiError
  | ShelleyStakeAddressWriteSignKeyError !FilePath !ApiError
  | ShelleyStakeAddressWriteVerKeyError !FilePath !ApiError
  deriving Show

renderShelleyStakeAddressCmdError :: ShelleyStakeAddressCmdError -> Text
renderShelleyStakeAddressCmdError err =
  case err of
    ShelleyStakeReadPoolOperatorKeyError fp keyErr ->
      "Error reading pool operator key at: " <> textShow fp <> " Error: " <> renderKeyError keyErr
    ShelleyStakeAddressConvError convErr -> renderConversionError convErr
    ShelleyStakeAddressReadFileError fp readErr ->
      "Error reading file at: " <> textShow fp <> " Error: " <> readErr
    ShelleyStakeAddressReadVerKeyError fp apiErr ->
      "Error while reading verification stake key at: " <> textShow fp <> " Error: " <> renderApiError apiErr
    ShelleyStakeAddressWriteCertError fp apiErr ->
      "Error while writing delegation certificate at: " <> textShow fp <> " Error: " <> renderApiError apiErr
    ShelleyStakeAddressWriteSignKeyError fp apiErr ->
      "Error while writing signing stake key at: " <> textShow fp <> " Error: " <> renderApiError apiErr
    ShelleyStakeAddressWriteVerKeyError fp apiErr ->
      "Error while writing verification stake key at: " <> textShow fp <> " Error: " <> renderApiError apiErr
    ShelleyStakeAddressKeyPairError bech32PrivKey bech32PubKey ->
      "Error while deriving the shelley verification key from bech32 private Key: " <> bech32PrivKey <>
      " Corresponding bech32 public key: " <> bech32PubKey
    ShelleyStakeAddressUnequalKeysError numVKeys numSKeys ->
      "Number of verification keys do not equal number of signing keys:" <>
      " Number of verification keys: " <> textShow numVKeys <>
      " Number of signing keys: " <> textShow numSKeys
    ShelleyStakeAddressUnequalNumberOfOutputFilesError numVKeyOuts numSKeyOuts ->
      "Number of specified output files are uneven: " <>
      " Number of verification key output files: " <> textShow numVKeyOuts <>
      " Number of signing key output files: " <> textShow numSKeyOuts
    ShelleyStakeAddressLessKeysThanOutsError numKeys numOuts ->
      "Number of input keys are less than the number of specified output files. " <>
      "Number of input keys: " <> textShow numKeys <>
      " Number of specified output files: " <> textShow numOuts
    ShelleyStakeAddressMoreKeysThanOutsError numKeys numOuts ->
      "Number of input keys are more than the number of specified output files. " <>
      "Number of input keys: " <> textShow numKeys <>
      " Number of specified output files: " <> textShow numOuts


runStakeAddressCmd :: StakeAddressCmd -> ExceptT ShelleyStakeAddressCmdError IO ()
runStakeAddressCmd (StakeAddressKeyGen vk sk) = runStakeAddressKeyGen vk sk
runStakeAddressCmd (StakeAddressBuild vk nw mOutputFp) = runStakeAddressBuild vk nw mOutputFp
runStakeAddressCmd (StakeKeyRegistrationCert stkKeyVerKeyFp outputFp) =
  runStakeKeyRegistrationCert stkKeyVerKeyFp outputFp
runStakeAddressCmd (StakeKeyDelegationCert stkKeyVerKeyFp stkPoolVerKeyFp outputFp) =
  runStakeKeyDelegationCert stkKeyVerKeyFp stkPoolVerKeyFp outputFp
runStakeAddressCmd (StakeKeyDeRegistrationCert stkKeyVerKeyFp outputFp) =
  runStakeKeyDeRegistrationCert stkKeyVerKeyFp outputFp
runStakeAddressCmd (StakeKeyITNConversion vks sks vkOutfps skOutfps) = runStakeKeyITNConversion vks sks vkOutfps skOutfps
runStakeAddressCmd cmd = liftIO $ putStrLn $ "runStakeAddressCmd: " ++ show cmd


--
-- Stake address command implementations
--

runStakeAddressKeyGen :: VerificationKeyFile -> SigningKeyFile -> ExceptT ShelleyStakeAddressCmdError IO ()
runStakeAddressKeyGen (VerificationKeyFile vkFp) (SigningKeyFile skFp) = do
  (vkey, skey) <- liftIO genKeyPair
  firstExceptT (ShelleyStakeAddressWriteVerKeyError vkFp)
    . newExceptT
    $ writeStakingVerificationKey vkFp (StakingVerificationKeyShelley vkey)
  --TODO: writeSigningKey should really come from Cardano.Config.Shelley.ColdKeys
  firstExceptT (ShelleyStakeAddressWriteSignKeyError skFp) . newExceptT $ writeSigningKey skFp (SigningKeyShelley skey)


runStakeAddressBuild :: VerificationKeyFile -> Network -> Maybe OutputFile
                     -> ExceptT ShelleyStakeAddressCmdError IO ()
runStakeAddressBuild (VerificationKeyFile stkVkeyFp) network mOutputFp =
  firstExceptT (ShelleyStakeAddressReadVerKeyError stkVkeyFp) $ do
    stkVKey <- ExceptT $ readStakingVerificationKey stkVkeyFp
    let rwdAddr = AddressShelleyReward (shelleyVerificationKeyRewardAddress network stkVKey)
        hexAddr = addressToHex rwdAddr
    case mOutputFp of
      Just (OutputFile fpath) -> liftIO . LBS.writeFile fpath $ textToLByteString hexAddr
      Nothing -> liftIO $ Text.putStrLn hexAddr


runStakeKeyRegistrationCert :: VerificationKeyFile -> OutputFile -> ExceptT ShelleyStakeAddressCmdError IO ()
runStakeKeyRegistrationCert (VerificationKeyFile vkFp) (OutputFile oFp) = do
  StakingVerificationKeyShelley stakeVkey <-
    firstExceptT (ShelleyStakeAddressReadVerKeyError vkFp) . newExceptT $ readStakingVerificationKey vkFp
  let regCert = shelleyRegisterStakingAddress (hashKey stakeVkey)
  firstExceptT (ShelleyStakeAddressWriteCertError oFp) . newExceptT $ writeCertificate oFp regCert


runStakeKeyDelegationCert
  :: VerificationKeyFile
  -- ^ Delegator stake verification key file.
  -> VerificationKeyFile
  -- ^ Delegatee stake pool verification key file.
  -> OutputFile
  -> ExceptT ShelleyStakeAddressCmdError IO ()
runStakeKeyDelegationCert (VerificationKeyFile stkKey) (VerificationKeyFile poolVKey) (OutputFile outFp) = do
  StakingVerificationKeyShelley stakeVkey <-
    firstExceptT (ShelleyStakeAddressReadVerKeyError stkKey) . newExceptT $ readStakingVerificationKey stkKey
  poolStakeVkey <- firstExceptT (ShelleyStakeReadPoolOperatorKeyError poolVKey) $
    readVerKey (OperatorKey StakePoolOperatorKey) poolVKey
  let delegCert = shelleyDelegateStake (hashKey stakeVkey) (hashKey poolStakeVkey)
  firstExceptT (ShelleyStakeAddressWriteCertError outFp) . newExceptT $ writeCertificate outFp delegCert


runStakeKeyDeRegistrationCert :: VerificationKeyFile -> OutputFile -> ExceptT ShelleyStakeAddressCmdError IO ()
runStakeKeyDeRegistrationCert (VerificationKeyFile vkFp) (OutputFile oFp) = do
  StakingVerificationKeyShelley stakeVkey <-
    firstExceptT (ShelleyStakeAddressReadVerKeyError vkFp)  . newExceptT $ readStakingVerificationKey vkFp
  let deRegCert = shelleyDeregisterStakingAddress (hashKey stakeVkey)
  firstExceptT (ShelleyStakeAddressWriteCertError oFp) . newExceptT $ writeCertificate oFp deRegCert


runStakeKeyITNConversion
  :: [VerificationKeyFile]
  -> [SigningKeyFile]
  -> [OutputFile]
  -- ^ Verification key output file paths
  -> [OutputFile]
  -- ^ Signing key output file paths
  -> ExceptT ShelleyStakeAddressCmdError IO ()
runStakeKeyITNConversion [] [] [] [] = return ()
runStakeKeyITNConversion vkeys [] [] [] = do
  bech32vKeys <- sequenceA [ firstExceptT ShelleyStakeAddressConvError . newExceptT $ readBech32 s
                           | VerificationKeyFile s <- vkeys
                           ]
  verificationKeys <- mapM (hoistEither . first ShelleyStakeAddressConvError . convertITNverificationKey) bech32vKeys

  mapM_ print verificationKeys

runStakeKeyITNConversion vkeys [] vouts [] = do
  let vKeysNum = length vkeys
      vOutsNum = length vouts

  equalNumberOfInsOuts vKeysNum vOutsNum

  sequence_ (runSingleITNKeyConversion <$> map Just vkeys <*> (take vOutsNum $ repeat Nothing) <*> vouts)

runStakeKeyITNConversion [] skeys [] [] = do
  bech32sKeys <- sequenceA [ firstExceptT ShelleyStakeAddressConvError . newExceptT $ readBech32 s
                           | SigningKeyFile s <- skeys
                           ]
  stakingKeys <- mapM (hoistEither . first ShelleyStakeAddressConvError . convertITNsigningKey) bech32sKeys

  mapM_ print stakingKeys

runStakeKeyITNConversion [] skeys [] souts = do
  let sKeysNum = length skeys
      sOutsNum = length souts

  equalNumberOfInsOuts sKeysNum sOutsNum

  sequence_ (runSingleITNKeyConversion <$> (take sOutsNum $ repeat Nothing) <*> map Just skeys <*> souts)

runStakeKeyITNConversion vkeys skeys [] [] = do
  -- Check that an equal number of keys have been entered
  equalNumKeys

  sequence_ (runSingleITNKeyPairConversion <$> vkeys <*> skeys <*> (take vKeysNum $ repeat Nothing))

 where
   vKeysNum = length vkeys
   sKeysNum = length skeys

   equalNumKeys :: ExceptT ShelleyStakeAddressCmdError IO ()
   equalNumKeys
     | vKeysNum /= sKeysNum = left $ ShelleyStakeAddressUnequalKeysError vKeysNum sKeysNum
     | otherwise = return ()

runStakeKeyITNConversion vkeys skeys vouts souts = do
  -- Check the number of verification key file paths, signing key file paths,
  -- and output file paths are all equal
  allEqualLength

  let outPairs = map Just $ zip vouts souts
  sequence_ (runSingleITNKeyPairConversion <$> vkeys <*> skeys <*> outPairs)

 where
   numVKeys = length vkeys
   numSKeys = length skeys
   numberOfInputs = numVKeys + numSKeys

   numSKeyOuts = length souts
   numVKeyOuts = length vouts
   numberOfOutputs = numSKeyOuts + numVKeyOuts

   allEqualLength :: ExceptT ShelleyStakeAddressCmdError IO ()
   allEqualLength
     | numVKeys /= numSKeys = left $ ShelleyStakeAddressUnequalKeysError numVKeys numSKeys
     | numVKeyOuts /= numSKeyOuts = left $ ShelleyStakeAddressUnequalNumberOfOutputFilesError numVKeyOuts numSKeyOuts
     | numberOfInputs < numberOfOutputs = left $ ShelleyStakeAddressLessKeysThanOutsError numberOfInputs numberOfOutputs
     | numberOfInputs > numberOfOutputs = left $ ShelleyStakeAddressMoreKeysThanOutsError numberOfInputs numberOfOutputs
     | otherwise = return ()


runSingleITNKeyConversion
  :: Maybe VerificationKeyFile
  -> Maybe SigningKeyFile
  -> OutputFile
  -> ExceptT ShelleyStakeAddressCmdError IO ()
runSingleITNKeyConversion (Just (VerificationKeyFile vk)) Nothing (OutputFile fp) = do
  bech32publicKey <- firstExceptT ShelleyStakeAddressConvError . newExceptT $ readBech32 vk
  v@(StakingVerificationKeyShelley (VKey _vkey)) <- hoistEither . first ShelleyStakeAddressConvError $ convertITNverificationKey bech32publicKey
  firstExceptT (ShelleyStakeAddressWriteVerKeyError fp) . newExceptT $ writeStakingVerificationKey fp v

runSingleITNKeyConversion Nothing (Just (SigningKeyFile sk)) (OutputFile fp) = do
  bech32privateKey <- firstExceptT ShelleyStakeAddressConvError . newExceptT $ readBech32 sk
  s@(SigningKeyShelley _sKey) <- hoistEither . first ShelleyStakeAddressConvError $ convertITNsigningKey bech32privateKey
  firstExceptT (ShelleyStakeAddressWriteSignKeyError fp) . newExceptT $ writeSigningKey fp s

runSingleITNKeyConversion _ _ _ = return () -- This case is currently impossible

runSingleITNKeyPairConversion
  :: VerificationKeyFile
  -> SigningKeyFile
  -> Maybe (OutputFile, OutputFile)
  -> ExceptT ShelleyStakeAddressCmdError IO ()
runSingleITNKeyPairConversion (VerificationKeyFile vk) (SigningKeyFile sk) mOutFile = do
  bech32publicKey <- firstExceptT ShelleyStakeAddressConvError . newExceptT $ readBech32 vk
  bech32privateKey <- firstExceptT ShelleyStakeAddressConvError . newExceptT $ readBech32 sk

  (signKey, shelleyVerKey) <- checkKeyPair bech32publicKey bech32privateKey

  case mOutFile of
    Just (OutputFile oSKey, OutputFile oVKey) -> do
      firstExceptT (ShelleyStakeAddressWriteSignKeyError oSKey) . newExceptT $ writeSigningKey oSKey signKey
      firstExceptT (ShelleyStakeAddressWriteVerKeyError oVKey) . newExceptT $ writeStakingVerificationKey oVKey shelleyVerKey
    Nothing -> do
      liftIO $ print shelleyVerKey
      liftIO $ print signKey

-- | Checks that the verification key corresponds to the given signing key
-- This does not need to be in 'IO' however the 'MonadFail' constraint
-- imposed by the ITN conversion functions forces us to use 'IO'
-- in order to report useful errors with 'Either'.
checkKeyPair
  :: Text
  -- ^ Bech32 public key
  -> Text
  -- ^ Bech32 private key
  -> ExceptT ShelleyStakeAddressCmdError IO (SigningKey, StakingVerificationKey)
checkKeyPair bech32publicKey bech32privateKey = do
  v@(StakingVerificationKeyShelley (VKey vkey)) <- hoistEither . first ShelleyStakeAddressConvError $ convertITNverificationKey bech32publicKey
  s@(SigningKeyShelley sKey) <- hoistEither . first ShelleyStakeAddressConvError $ convertITNsigningKey bech32privateKey

  if DSIGN.deriveVerKeyDSIGN sKey == vkey
  then return (s, v)
  else left $ ShelleyStakeAddressKeyPairError bech32privateKey bech32publicKey

equalNumberOfInsOuts :: Int  -> Int  -> ExceptT ShelleyStakeAddressCmdError IO ()
equalNumberOfInsOuts ins outs
     | ins < outs = left $ ShelleyStakeAddressLessKeysThanOutsError ins outs
     | ins > outs = left $ ShelleyStakeAddressMoreKeysThanOutsError ins outs
     | otherwise = return ()