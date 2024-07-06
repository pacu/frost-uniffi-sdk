use uniffi;

use std::{clone, error::Error, sync::Arc};

use orchard::{
    keys::{FullViewingKey, SpendValidatingKey, SpendingKey},
};
use zcash_address::unified::{Address, Encoding, Receiver};
use zcash_primitives::zip32::AccountId;
use zcash_protocol::consensus::{Network, NetworkConstants, NetworkType, Parameters};
use zip32::Scope;

#[derive(uniffi::Enum, Clone, Debug)]
pub enum ZcashNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl ZcashNetwork {
    fn to_network_type(&self) -> NetworkType {
        match self {
            Self::Mainnet => NetworkType::Main,
            Self::Testnet => NetworkType::Test,
            Self::Regtest => NetworkType::Regtest,
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
            NetworkType::Regtest => Self::Testnet,
        }
    }
}

#[derive(uniffi::Error, Debug)]
pub enum OrchardKeyError {
    KeyDerivationError{
        message: String
    },
    SerializationError,
    DeserializationError,
    OtherError {
        error_message: String
    },
}

#[derive(uniffi::Object)]
pub struct OrchardAddress {
    network: ZcashNetwork,
    addr: Arc<Address>,
}

impl OrchardAddress {
    fn new_from_string(string: String) -> Result<OrchardAddress, OrchardKeyError> {
        let (network, addr) = zcash_address::unified::Address::decode(&string)
            .map_err(|_| OrchardKeyError::DeserializationError)?;

        Ok(OrchardAddress {
            network: ZcashNetwork::new_from_network_type(network),
            addr: Arc::new(addr),
        })
    }
    fn string_encoded(&self) -> String {
        self.addr.encode(&self.network.to_network_type())
    }
}

#[derive(uniffi::Object, Clone)]
pub struct OrchardFullViewingKey {
    network: ZcashNetwork,
    fvk: Arc<FullViewingKey>,
}

impl OrchardFullViewingKey {
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
            AccountId::try_from(0)
                .map_err(|e| {
                    OrchardKeyError::KeyDerivationError { message: e.to_string() }
        })?,
        )
        .map_err(|e| OrchardKeyError::KeyDerivationError{ message: e.to_string() })?;

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
                fvk: Arc::new(f),
            }),
            None => Err(OrchardKeyError::KeyDerivationError {
               message: "could not derive FROST fvk from resulting bytes".to_string(),
            }),
        }
    }

    fn string_encoded(&self) -> String {
        "".to_string()
    }

    fn derive_address(&self) -> Result<OrchardAddress, OrchardKeyError> {
        let s = self.fvk.address_at(0u64, Scope::External);

        let orchard_receiver = Receiver::Orchard(s.to_raw_address_bytes());

        let ua = zcash_address::unified::Address::try_from_items(vec![orchard_receiver])
            .map_err(|_| OrchardKeyError::SerializationError)?;

        Ok(OrchardAddress {
            network: self.network.clone(),
            addr: Arc::new(ua),
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

        let s = orchard_fvk.unwrap().fvk.address_at(0u64, Scope::External);

        let orchard_receiver = Receiver::Orchard(s.to_raw_address_bytes());

        let ua = zcash_address::unified::Address::try_from_items(vec![orchard_receiver]);

        let string = ua
            .unwrap()
            .encode(&zcash_protocol::consensus::Network::TestNetwork.network_type());

        print!("{}", string);
        // match orchard_fvk {
        //     Ok(fvk) => assert!(true),
        //     Err(e) => panic!("failed with error {:?}", e)
        // }
    }
}
