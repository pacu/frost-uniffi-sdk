use uniffi;
use bip0039::{English, Mnemonic};
use std::sync::Arc;

use orchard::keys::{
    CommitIvkRandomness, FullViewingKey, NullifierDerivingKey, SpendValidatingKey, SpendingKey,
};
use zcash_address::unified::{Address, Encoding, Receiver};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::zip32::AccountId;
use zcash_protocol::consensus::{Network, NetworkConstants, NetworkType};
use zip32::Scope;

#[derive(uniffi::Enum, Clone, Debug)]
pub enum ZcashNetwork {
    Mainnet,
    Testnet,
    #[cfg(feature = "regtest")]
    Regtest,
}

impl ZcashNetwork {
    fn to_network_type(&self) -> NetworkType {
        match self {
            Self::Mainnet => NetworkType::Main,
            Self::Testnet => NetworkType::Test,
            #[cfg(feature = "regtest")]
            Self::Regtest => NetworkType::Regtest,
        }
    }

    fn to_network_parameters(&self) -> Network {
        match self {
            Self::Mainnet => Network::MainNetwork,
            Self::Testnet => Network::TestNetwork,
            #[cfg(feature = "regtest")]
            Self::Regtest => Network::TestNetwork,
        }
    }
    fn new(network: Network) -> Self {
        match network {
            Network::MainNetwork => Self::Mainnet,
            Network::TestNetwork => Self::Testnet,
        }
    }

    fn new_from_network_type(network_type: NetworkType) -> Self {
        match network_type {
            NetworkType::Main => Self::Mainnet,
            NetworkType::Test => Self::Testnet,
            #[cfg(not(feature = "regtest"))]
            NetworkType::Regtest => Self::Testnet,
            #[cfg(feature = "regtest")]
            NetworkType::Regtest => Self::Regtest,
        }
    }
}

#[derive(uniffi::Error, Debug, Clone)]
pub enum OrchardKeyError {
    KeyDerivationError { message: String },
    SerializationError,
    DeserializationError,
    OtherError { error_message: String },
}

/// This responds to Backup and DKG requirements
/// for FROST.
/// 
/// - Note: See [FROST Book backup section](https://frost.zfnd.org/zcash/technical-details.html#backing-up-key-shares)
#[derive(uniffi::Record, Clone)]
pub struct OrchardKeyParts {
    pub nk: Vec<u8>,
    pub rivk: Vec<u8>,
}

impl OrchardKeyParts {
    fn random(network: Network) -> Result<OrchardKeyParts, OrchardKeyError> {
        let mnemonic = Mnemonic::<English>::generate(bip0039::Count::Words24);
        let random_entropy = mnemonic.entropy();
        let spending_key = SpendingKey::from_zip32_seed(random_entropy, network.coin_type(), AccountId::ZERO)
            .map_err(|e| OrchardKeyError::KeyDerivationError { message: e.to_string() })?;

        let nk = NullifierDerivingKey::from(&spending_key);
        let rivk = CommitIvkRandomness::from(&spending_key);

        Ok(
            OrchardKeyParts {
                nk: nk.to_bytes().to_vec(),
                rivk: rivk.to_bytes().to_vec(),
            }
        )
    }   
}
#[derive(uniffi::Object)]

pub struct OrchardAddress {
    network: ZcashNetwork,
    addr: Address,
}

impl OrchardAddress {
    fn new_from_string(string: String) -> Result<OrchardAddress, OrchardKeyError> {
        let (network, addr) = zcash_address::unified::Address::decode(&string)
            .map_err(|_| OrchardKeyError::DeserializationError)?;

        Ok(OrchardAddress {
            network: ZcashNetwork::new_from_network_type(network),
            addr: addr,
        })
    }

    fn string_encoded(&self) -> String {
        self.addr.encode(&self.network.to_network_type())
    }
}

#[derive(uniffi::Object, Clone)]
pub struct OrchardFullViewingKey {
    network: ZcashNetwork,
    fvk: FullViewingKey,
}

impl OrchardFullViewingKey {
    /// Creates an [`OrchardFullViewingKey`] from its composing parts.
    ///
    /// - Note: See [FROST Book backup section](https://frost.zfnd.org/zcash/technical-details.html#backing-up-key-shares)
    fn new_from_parts(
        ak: &SpendValidatingKey,
        nk: &NullifierDerivingKey,
        rivk: &CommitIvkRandomness,
        network: Network,
    ) -> Result<OrchardFullViewingKey, OrchardKeyError> {
        let fvk = FullViewingKey::from_checked_parts(ak.clone(), nk.clone(), rivk.clone());

        Ok(OrchardFullViewingKey {
            network: ZcashNetwork::new(network),
            fvk: fvk,
        })
    }

    /// Creates a new FullViewingKey from a ZIP-32 Seed and validating key
    /// using the `Network` coin type on `AccountId(0u32)`
    /// see https://frost.zfnd.org/zcash/technical-details.html for more
    /// information.
    fn new_from_validating_key_and_seed(
        validating_key: OrchardSpendValidatingKey,
        zip_32_seed: &[u8],
        network: Network,
    ) -> Result<Self, OrchardKeyError> {
        let sk = SpendingKey::from_zip32_seed(
            zip_32_seed,
            network.coin_type(),
            AccountId::try_from(0).map_err(|e| OrchardKeyError::KeyDerivationError {
                message: e.to_string(),
            })?,
        )
        .map_err(|e| OrchardKeyError::KeyDerivationError {
            message: e.to_string(),
        })?;

        // derive the FVK from the random spending key.
        let random_fvk = FullViewingKey::from(&sk);
        // get its bytes
        let mut fvk_bytes = random_fvk.to_bytes().clone();
        // get bytes from provided `ak`
        let ak_bytes = validating_key.key.as_ref().to_bytes();

        // now we will replace the raw bytes of the current ak with the
        // ones generated with FROST. This is not elegant but will do
        // for now.
        fvk_bytes[0..32].copy_from_slice(&<[u8; 32]>::from(ak_bytes));

        // now we will construct the viewing key from it
        let frosty_fvk = FullViewingKey::from_bytes(&fvk_bytes);

        match frosty_fvk {
            Some(f) => Ok(OrchardFullViewingKey {
                network: ZcashNetwork::new(network),
                fvk: f,
            }),
            None => Err(OrchardKeyError::KeyDerivationError {
                message: "could not derive FROST fvk from resulting bytes".to_string(),
            }),
        }
    }

    fn decode(
        string_enconded: String,
        network: Network,
    ) -> Result<OrchardFullViewingKey, OrchardKeyError> {
        let ufvk = UnifiedFullViewingKey::decode(&network, &string_enconded)
            .map_err(|_| OrchardKeyError::DeserializationError)?;

        match ufvk.orchard() {
            Some(viewing_key) => {
                let orchard_vk = OrchardFullViewingKey {
                    fvk: viewing_key.clone(),
                    network: ZcashNetwork::new(network),
                };
                Ok(orchard_vk)
            }
            None => Err(OrchardKeyError::KeyDerivationError {
                message: "No Orchard key on Unified Viewing key".to_string(),
            }),
        }
    }

    fn encode(&self) -> Result<String, OrchardKeyError> {
        let ufvk = UnifiedFullViewingKey::from_orchard_fvk(
            self.fvk.clone() as orchard::keys::FullViewingKey
        )
        .map_err(|e| OrchardKeyError::KeyDerivationError {
            message: e.to_string(),
        })?;

        Ok(ufvk.encode(&self.network.to_network_parameters()))
    }

    /// derives external address 0 of this Orchard Full viewing key.
    fn derive_address(&self) -> Result<OrchardAddress, OrchardKeyError> {
        let s = self.fvk.address_at(0u64, Scope::External);

        let orchard_receiver = Receiver::Orchard(s.to_raw_address_bytes());

        let ua = zcash_address::unified::Address::try_from_items(vec![orchard_receiver])
            .map_err(|_| OrchardKeyError::SerializationError)?;

        Ok(OrchardAddress {
            network: self.network.clone(),
            addr: ua,
        })
    }
}

#[derive(uniffi::Object)]
pub struct OrchardSpendValidatingKey {
    key: Arc<SpendValidatingKey>,
}

pub struct OrchardSpentAuthorizingKey {}

impl OrchardSpendValidatingKey {
    fn from_bytes(bytes: &[u8]) -> Result<OrchardSpendValidatingKey, OrchardKeyError> {
        SpendValidatingKey::from_bytes(&bytes)
            .map_or(Err(OrchardKeyError::DeserializationError), |s| {
                Ok(OrchardSpendValidatingKey { key: Arc::new(s) })
            })
    }
}

impl OrchardSpentAuthorizingKey {
    fn from_bytes(bytes: &[u8]) -> Result<OrchardSpentAuthorizingKey, OrchardKeyError> {
        Err(OrchardKeyError::DeserializationError)
    }
}

mod tests {
    use zcash_address::{
        unified::{Encoding, Receiver},
        ToAddress,
    };
    use zcash_protocol::consensus::Parameters;
    use zip32::Scope;

    use super::{OrchardFullViewingKey, OrchardSpendValidatingKey};

    /// this verifying key is from the "FROST Book"
    /// https://frost.zfnd.org/zcash/ywallet-demo.html
    #[test]
    fn test_ak_generates_spend_validating_key() {
        let verifying_hex_string =
            "d2bf40ca860fb97e9d6d15d7d25e4f17d2e8ba5dd7069188cbf30b023910a71b";
        let hex_bytes = hex::decode(verifying_hex_string).unwrap();

        assert!(OrchardSpendValidatingKey::from_bytes(&hex_bytes).is_ok())
    }

    /// this verifying key is from the "FROST Book"
    /// https://frost.zfnd.org/zcash/ywallet-demo.html
    /// seed was generated with https://iancoleman.io/bip39/
    /// don't use it yourself. Don't even think about it!
    #[test]
    fn test_ak_and_seed_creates_a_valid_viewing_key() {
        let verifying_hex_string =
            "d2bf40ca860fb97e9d6d15d7d25e4f17d2e8ba5dd7069188cbf30b023910a71b";
        let hex_bytes = hex::decode(verifying_hex_string).unwrap();

        let verifying_key = OrchardSpendValidatingKey::from_bytes(&hex_bytes).unwrap();

        let random_seed_bytes = hex::decode("659ce2e5362b515f30c38807942a10c18a3a2f7584e7135b3523d5e72bb796cc64c366a8a6bfb54a5b32c41720bdb135758c1afacac3e72fd5974be0846bf7a5").unwrap();

        let orchard_fvk = OrchardFullViewingKey::new_from_validating_key_and_seed(
            verifying_key,
            &random_seed_bytes,
            zcash_protocol::consensus::Network::TestNetwork,
        );

        let s = orchard_fvk
            .clone()
            .unwrap()
            .fvk
            .address_at(0u64, Scope::External);

        let orchard_receiver = Receiver::Orchard(s.to_raw_address_bytes());

        let ua = zcash_address::unified::Address::try_from_items(vec![orchard_receiver]);

        let string = ua
            .unwrap()
            .encode(&zcash_protocol::consensus::Network::TestNetwork.network_type());

        print!("{}", string);
        match orchard_fvk {
            Ok(fvk) => assert!(true),
            Err(e) => panic!("failed with error {:?}", e),
        }
    }
}
