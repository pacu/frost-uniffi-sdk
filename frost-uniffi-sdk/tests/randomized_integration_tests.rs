use frost_uniffi_sdk::{
    coordinator::Message, trusted_dealer::trusted_dealer_keygen_from_configuration, Configuration,
};

use frost_uniffi_sdk::{
    coordinator::new_signing_package, participant::FrostSignatureShare, ParticipantIdentifier,
};
use std::collections::HashMap;

mod helpers;
use helpers::{key_package, round_1};
use rand::thread_rng;

#[cfg(not(feature = "redpallas"))]
use frost_uniffi_sdk::coordinator::aggregate;
#[cfg(feature = "redpallas")]
use frost_uniffi_sdk::{
    randomized::tests::helpers::round_2,
    randomized::{
        coordinator::{aggregate, verify_randomized_signature},
        participant::sign,
        randomizer::FrostRandomizer,
    },
};
#[cfg(not(feature = "redpallas"))]
use helpers::round_2;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas::RandomizedParams;

#[cfg(feature = "redpallas")]
type E = reddsa::frost::redpallas::PallasBlake2b512;
#[cfg(not(feature = "redpallas"))]
type E = frost_ed25519::Ed25519Sha512;

fn test_signing_key() -> Vec<u8> {
    #[cfg(feature = "redpallas")]
    return vec![]; //hex::decode("f500df73b2b416bec6a2b6bbb44e97164e05520b63aa27554cfc7ba82f5ba215")
                   // .unwrap();

    #[cfg(not(feature = "redpallas"))]
    return vec![
        123, 28, 51, 211, 245, 41, 29, 133, 222, 102, 72, 51, 190, 177, 173, 70, 159, 127, 182, 2,
        90, 14, 199, 139, 58, 121, 12, 110, 19, 169, 131, 4,
    ];
}

#[cfg(feature = "redpallas")]
#[test]
fn test_randomized_trusted_from_configuration_with_secret() {
    use frost_uniffi_sdk::randomized::coordinator::verify_randomized_signature;

    let mut rng = thread_rng();

    let secret: Vec<u8> = test_signing_key();
    let secret_config = Configuration {
        min_signers: 2,
        max_signers: 3,
        secret,
    };

    let (pubkeys, shares) = trusted_dealer_keygen_from_configuration::<E>(&secret_config).unwrap();
    let key_packages = key_package::<E>(&shares);
    let (nonces, commitments) = round_1::<E>(&mut rng, &key_packages);
    let message = Message {
        data: "i am a message".as_bytes().to_vec(),
    };

    let commitments = commitments.into_iter().map(|c| c.1).collect();
    let signing_package = new_signing_package(message.clone(), commitments).unwrap();
    let mut signature_shares: HashMap<ParticipantIdentifier, FrostSignatureShare> = HashMap::new();

    let pallas_signing_package = signing_package.to_signing_package().unwrap();
    let randomized_params = RandomizedParams::new(
        pubkeys.into_public_key_package().unwrap().verifying_key(),
        &pallas_signing_package,
        rng,
    )
    .unwrap();
    let randomizer = randomized_params.randomizer();

    let frost_randomizer = FrostRandomizer::from_randomizer::<E>(*randomizer).unwrap();

    for participant_identifier in nonces.keys() {
        let key_package = key_packages[participant_identifier].clone();

        let nonces = nonces[participant_identifier].clone();

        let signature_share = sign(
            signing_package.clone(),
            nonces,
            key_package,
            &frost_randomizer,
        )
        .unwrap();

        signature_shares.insert(participant_identifier.clone(), signature_share);
    }

    let randomizer =
        FrostRandomizer::from_randomizer::<E>(*randomized_params.randomizer()).unwrap();

    let group_signature = aggregate(
        signing_package,
        signature_shares.into_iter().map(|s| s.1).collect(),
        pubkeys.clone(),
        randomizer.clone(),
    )
    .unwrap();

    let verify_signature =
        verify_randomized_signature(randomizer, message, group_signature, pubkeys);

    match verify_signature {
        Ok(()) => assert!(true),
        Err(e) => {
            assert!(false, "signature verification failed with error: {e:?}")
        }
    }
}
#[cfg(feature = "redpallas")]
#[test]
fn check_keygen_with_dealer_with_secret_with_large_num_of_signers() {
    let mut rng = thread_rng();
    let secret: Vec<u8> = test_signing_key();
    let secret_config = Configuration {
        min_signers: 14,
        max_signers: 20,
        secret,
    };

    let (pubkeys, shares) = trusted_dealer_keygen_from_configuration::<E>(&secret_config).unwrap();

    let key_packages = key_package::<E>(&shares);
    let (nonces, commitments) = round_1::<E>(&mut rng, &key_packages);
    let message = Message {
        data: "i am a message".as_bytes().to_vec(),
    };

    let (signing_package, signature_shares, randomized_params) = round_2(
        &mut rng,
        &nonces,
        &key_packages,
        commitments,
        pubkeys.clone(),
        message.clone(),
    );

    let frost_randomizer =
        FrostRandomizer::from_randomizer::<E>(*randomized_params.randomizer()).unwrap();

    let group_signature = aggregate(
        signing_package,
        signature_shares.into_iter().map(|s| s.1).collect(),
        pubkeys.clone(),
        frost_randomizer.clone(),
    )
    .unwrap();

    assert!(
        verify_randomized_signature(frost_randomizer, message, group_signature, pubkeys).is_ok()
    )
}
