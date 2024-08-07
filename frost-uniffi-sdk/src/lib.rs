#[cfg(not(feature = "redpallas"))]
type E = frost_ed25519::Ed25519Sha512;
#[cfg(feature = "redpallas")]
type E = reddsa::frost::redpallas::PallasBlake2b512;
pub mod coordinator;
pub mod dkg;
pub mod error;
pub mod participant;
#[cfg(feature = "redpallas")]
pub mod randomized;
pub mod serialization;
pub mod trusted_dealer;
pub mod orchard;
use crate::trusted_dealer::{trusted_dealer_keygen, trusted_dealer_keygen_from_configuration};

use frost_core::{
    keys::{IdentifierList, KeyPackage, PublicKeyPackage, VerifyingShare},
    Ciphersuite, Error, Identifier, VerifyingKey,
};

use rand::thread_rng;
use std::{
    collections::{BTreeMap, HashMap},
    hash::Hash,
};

uniffi::setup_scaffolding!();

#[derive(uniffi::Record)]
pub struct ParticipantList {
    pub identifiers: Vec<ParticipantIdentifier>,
}

#[derive(uniffi::Record, Hash, Eq, PartialEq, Clone, Debug)]
pub struct ParticipantIdentifier {
    pub data: String,
}

#[derive(uniffi::Record)]
pub struct TrustedKeyGeneration {
    pub secret_shares: HashMap<ParticipantIdentifier, FrostSecretKeyShare>,
    pub public_key_package: FrostPublicKeyPackage,
}

#[derive(uniffi::Record)]
pub struct FrostSecretKeyShare {
    pub identifier: ParticipantIdentifier,
    pub data: Vec<u8>,
}

#[derive(uniffi::Record, Clone)]
pub struct FrostPublicKeyPackage {
    pub verifying_shares: HashMap<ParticipantIdentifier, String>,
    pub verifying_key: String,
}

#[derive(uniffi::Record, Clone)]
pub struct Configuration {
    pub min_signers: u16,
    pub max_signers: u16,
    pub secret: Vec<u8>,
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum ConfigurationError {
    #[error("Number of maximum signers in invalid.")]
    InvalidMaxSigners,
    #[error("Number of minimum signers in invalid.")]
    InvalidMinSigners,
    #[error("One or more of the custom Identifiers provided are invalid.")]
    InvalidIdentifier,
    #[error("There's a problem with this configuration.")]
    UnknownError,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FrostError {
    /// min_signers is invalid
    #[error("min_signers must be at least 2 and not larger than max_signers")]
    InvalidMinSigners,
    /// max_signers is invalid
    #[error("max_signers must be at least 2")]
    InvalidMaxSigners,
    /// max_signers is invalid
    #[error("coefficients must have min_signers-1 elements")]
    InvalidCoefficients,
    /// This identifier is unserializable.
    #[error("Malformed identifier is unserializable.")]
    MalformedIdentifier,
    /// This identifier is duplicated.
    #[error("Duplicated identifier.")]
    DuplicatedIdentifier,
    /// This identifier does not belong to a participant in the signing process.
    #[error("Unknown identifier.")]
    UnknownIdentifier,
    /// Incorrect number of identifiers.
    #[error("Incorrect number of identifiers.")]
    IncorrectNumberOfIdentifiers,
    /// The encoding of a signing key was malformed.
    #[error("Malformed signing key encoding.")]
    MalformedSigningKey,
    /// The encoding of a verifying key was malformed.
    #[error("Malformed verifying key encoding.")]
    MalformedVerifyingKey,
    /// The encoding of a signature was malformed.
    #[error("Malformed signature encoding.")]
    MalformedSignature,
    /// Signature verification failed.
    #[error("Invalid signature.")]
    InvalidSignature,
    /// Duplicated shares provided
    #[error("Duplicated shares provided.")]
    DuplicatedShares,
    /// Incorrect number of shares.
    #[error("Incorrect number of shares.")]
    IncorrectNumberOfShares,
    /// Commitment equals the identity
    #[error("Commitment equals the identity.")]
    IdentityCommitment,
    /// The participant's commitment is missing from the Signing Package
    #[error("The Signing Package must contain the participant's Commitment.")]
    MissingCommitment,
    /// The participant's commitment is incorrect
    #[error("The participant's commitment is incorrect.")]
    IncorrectCommitment,
    /// Incorrect number of commitments.
    #[error("Incorrect number of commitments.")]
    IncorrectNumberOfCommitments,

    #[error("Invalid signature share.")]
    InvalidSignatureShare {
        /// The identifier of the signer whose share validation failed.
        culprit: ParticipantIdentifier,
    },
    /// Secret share verification failed.
    #[error("Invalid secret share.")]
    InvalidSecretShare,
    /// Round 1 package not found for Round 2 participant.
    #[error("Round 1 package not found for Round 2 participant.")]
    PackageNotFound,
    /// Incorrect number of packages.
    #[error("Incorrect number of packages.")]
    IncorrectNumberOfPackages,
    /// The incorrect package was specified.
    #[error("The incorrect package was specified.")]
    IncorrectPackage,
    /// The ciphersuite does not support DKG.
    #[error("The ciphersuite does not support DKG.")]
    DKGNotSupported,
    /// The proof of knowledge is not valid.
    #[error("The proof of knowledge is not valid.")]
    InvalidProofOfKnowledge {
        /// The identifier of the signer whose share validation failed.
        culprit: ParticipantIdentifier,
    },
    /// Error in scalar Field.
    #[error("Error in scalar Field.")]
    FieldError { message: String },
    /// Error in elliptic curve Group.
    #[error("Error in elliptic curve Group.")]
    GroupError { message: String },
    /// Error in coefficient commitment deserialization.
    #[error("Invalid coefficient")]
    InvalidCoefficient,
    /// The ciphersuite does not support deriving identifiers from strings.
    #[error("The ciphersuite does not support deriving identifiers from strings.")]
    IdentifierDerivationNotSupported,
    /// Error serializing value.
    #[error("Error serializing value.")]
    SerializationError,
    /// Error deserializing value.
    #[error("Error deserializing value.")]
    DeserializationError,
    #[error("DKG part 2 couldn't be started because of an invalid number of commitments")]
    DKGPart2IncorrectNumberOfCommitments,
    #[error("DKG part 2 couldn't be started because of an invalid number of packages")]
    DKGPart2IncorrectNumberOfPackages,
    #[error(
        "DKG part 3 couldn't be started because packages for round 1 are incorrect or corrupted."
    )]
    DKGPart3IncorrectRound1Packages,
    #[error("DKG part 3 couldn't be started because of an invalid number of packages.")]
    DKGPart3IncorrectNumberOfPackages,
    #[error("A sender identified from round 1 is not present within round 2 packages.")]
    DKGPart3PackageSendersMismatch,

    #[error("Key Package is invalid.")]
    InvalidKeyPackage,
    #[error("Secret Key couldn't be verified.")]
    InvalidSecretKey,

    #[error("DKG couldn't be started because of an invalid number of signers.")]
    InvalidConfiguration,

    #[error("Unexpected Error.")]
    UnexpectedError,
}
#[uniffi::export]
pub fn validate_config(config: &Configuration) -> Result<(), ConfigurationError> {
    if config.min_signers < 2 {
        return Err(ConfigurationError::InvalidMinSigners);
    }

    if config.max_signers < 2 {
        return Err(ConfigurationError::InvalidMaxSigners);
    }

    if config.min_signers > config.max_signers {
        return Err(ConfigurationError::InvalidMinSigners);
    }

    Ok(())
}

#[derive(uniffi::Record, Clone)]
pub struct FrostKeyPackage {
    pub identifier: ParticipantIdentifier,
    pub data: Vec<u8>,
}

#[uniffi::export]
pub fn verify_and_get_key_package_from(
    secret_share: FrostSecretKeyShare,
) -> Result<FrostKeyPackage, FrostError> {
    secret_share
        .into_key_package::<E>()
        .map_err(|_| FrostError::InvalidSecretKey)
}

#[uniffi::export]
pub fn trusted_dealer_keygen_from(
    configuration: Configuration,
) -> Result<TrustedKeyGeneration, FrostError> {
    let (pubkey, secret_shares) = trusted_dealer_keygen_from_configuration::<E>(&configuration)
        .map_err(FrostError::map_err)?;

    Ok(TrustedKeyGeneration {
        public_key_package: pubkey,
        secret_shares,
    })
}

#[uniffi::export]
pub fn trusted_dealer_keygen_with_identifiers(
    configuration: Configuration,
    participants: ParticipantList,
) -> Result<TrustedKeyGeneration, FrostError> {
    if configuration.max_signers as usize != participants.identifiers.len() {
        return Err(FrostError::InvalidMaxSigners);
    }

    let mut custom_identifiers: Vec<Identifier<E>> =
        Vec::with_capacity(participants.identifiers.capacity());

    for identifier in participants.identifiers.clone().into_iter() {
        let identifier = identifier
            .into_identifier()
            .map_err(|_| FrostError::MalformedIdentifier)?;
        custom_identifiers.push(identifier);
    }

    let list = IdentifierList::Custom(&custom_identifiers);

    let mut rng = thread_rng();

    let trust_dealt_keys =
        trusted_dealer_keygen(&configuration, list, &mut rng).map_err(FrostError::map_err)?;

    let pubkey = FrostPublicKeyPackage::from_public_key_package::<E>(trust_dealt_keys.public_keys)
        .map_err(FrostError::map_err)?;

    let mut hash_map: HashMap<ParticipantIdentifier, FrostSecretKeyShare> = HashMap::new();

    for (k, v) in trust_dealt_keys.secret_shares {
        hash_map.insert(
            ParticipantIdentifier::from_identifier(k).map_err(FrostError::map_err)?,
            FrostSecretKeyShare::from_secret_share::<E>(v).map_err(FrostError::map_err)?,
        );
    }

    Ok(TrustedKeyGeneration {
        public_key_package: pubkey,
        secret_shares: hash_map,
    })
}

impl FrostKeyPackage {
    pub fn from_key_package<C: Ciphersuite>(key_package: &KeyPackage<C>) -> Result<Self, Error<C>> {
        let serialized_package = key_package.serialize()?;
        let identifier = key_package.identifier();
        Ok(FrostKeyPackage {
            identifier: ParticipantIdentifier::from_identifier(*identifier)?,
            data: serialized_package,
        })
    }

    pub fn into_key_package<C: Ciphersuite>(&self) -> Result<KeyPackage<C>, Error<C>> {
        KeyPackage::deserialize(&self.data)
    }
}

impl ParticipantIdentifier {
    pub fn from_json_string<C: Ciphersuite>(string: &str) -> Option<ParticipantIdentifier> {
        let identifier: Result<Identifier<C>, serde_json::Error> = serde_json::from_str(string);
        match identifier {
            Ok(_) => Some(ParticipantIdentifier {
                data: string.to_string(),
            }),
            Err(_) => None,
        }
    }

    pub fn from_identifier<C: Ciphersuite>(
        identifier: frost_core::Identifier<C>,
    ) -> Result<ParticipantIdentifier, frost_core::Error<C>> {
        Ok(ParticipantIdentifier {
            data: serde_json::to_string(&identifier).map_err(|_| Error::SerializationError)?,
        })
    }

    pub fn into_identifier<C: Ciphersuite>(
        &self,
    ) -> Result<frost_core::Identifier<C>, frost_core::Error<C>> {
        let identifier: Identifier<C> = serde_json::from_str(&self.data)
            .map_err(|_| frost_core::Error::DeserializationError)?;

        Ok(identifier)
    }
}

impl FrostSecretKeyShare {
    pub fn from_secret_share<C: Ciphersuite>(
        secret_share: frost_core::keys::SecretShare<C>,
    ) -> Result<FrostSecretKeyShare, frost_core::Error<C>> {
        let identifier = ParticipantIdentifier::from_identifier(*secret_share.identifier())?;
        let serialized_share = secret_share.serialize()?;

        Ok(FrostSecretKeyShare {
            identifier,
            data: serialized_share,
        })
    }

    pub fn to_secret_share<C: Ciphersuite>(
        &self,
    ) -> Result<frost_core::keys::SecretShare<C>, frost_core::Error<C>> {
        let identifier = self.identifier.into_identifier::<C>()?;

        let secret_share = frost_core::keys::SecretShare::deserialize(&self.data)?;

        if identifier != *secret_share.identifier() {
            Err(frost_core::Error::UnknownIdentifier)
        } else {
            Ok(secret_share)
        }
    }

    pub fn into_key_package<C: Ciphersuite>(&self) -> Result<FrostKeyPackage, FrostError> {
        let secret_share = self.to_secret_share::<C>().map_err(FrostError::map_err)?;

        let key_package =
            frost_core::keys::KeyPackage::try_from(secret_share).map_err(FrostError::map_err)?;

        FrostKeyPackage::from_key_package(&key_package).map_err(FrostError::map_err)
    }
}

impl FrostPublicKeyPackage {
    pub fn from_public_key_package<C: Ciphersuite>(
        key_package: frost_core::keys::PublicKeyPackage<C>,
    ) -> Result<FrostPublicKeyPackage, frost_core::Error<C>> {
        let verifying_shares = key_package.verifying_shares();
        let verifying_key = key_package.verifying_key();

        let mut shares: HashMap<ParticipantIdentifier, String> = HashMap::new();

        for (k, v) in verifying_shares {
            shares.insert(
                ParticipantIdentifier::from_identifier(*k)?,
                hex::encode(v.serialize()),
            );
        }

        Ok(Self {
            verifying_shares: shares,
            verifying_key: hex::encode(verifying_key.serialize()),
        })
    }

    pub fn into_public_key_package(&self) -> Result<PublicKeyPackage<E>, Error<E>> {
        let raw_verifying_key =
            hex::decode(self.verifying_key.clone()).map_err(|_| Error::DeserializationError)?;

        let verifying_key_bytes = raw_verifying_key[0..32]
            .try_into()
            .map_err(|_| Error::DeserializationError)?;

        let verifying_key = VerifyingKey::deserialize(verifying_key_bytes)
            .map_err(|_| Error::DeserializationError)?;

        let mut btree_map: BTreeMap<Identifier<E>, VerifyingShare<E>> = BTreeMap::new();
        for (k, v) in self.verifying_shares.clone() {
            let identifier = k.into_identifier()?;

            let raw_verifying_share = hex::decode(v).map_err(|_| Error::DeserializationError)?;

            let verifying_share_bytes: [u8; 32] = raw_verifying_share[0..32]
                .try_into()
                .map_err(|_| Error::DeserializationError)?;

            let verifying_share = VerifyingShare::deserialize(verifying_share_bytes)?;

            btree_map.insert(identifier, verifying_share);
        }

        Ok(PublicKeyPackage::new(btree_map, verifying_key))
    }
}

#[uniffi::export]
pub fn identifier_from_json_string(string: String) -> Option<ParticipantIdentifier> {
    ParticipantIdentifier::from_json_string::<E>(string.as_str())
}

#[uniffi::export]
pub fn identifier_from_string(string: String) -> Result<ParticipantIdentifier, FrostError> {
    let identifier = Identifier::<E>::derive(string.as_bytes()).map_err(FrostError::map_err)?;

    let participant =
        ParticipantIdentifier::from_identifier(identifier).map_err(FrostError::map_err)?;
    Ok(participant)
}

#[uniffi::export]
pub fn identifier_from_uint16(unsigned_uint: u16) -> Result<ParticipantIdentifier, FrostError> {
    let identifier = Identifier::<E>::try_from(unsigned_uint).map_err(FrostError::map_err)?;

    let participant =
        ParticipantIdentifier::from_identifier(identifier).map_err(FrostError::map_err)?;
    Ok(participant)
}
