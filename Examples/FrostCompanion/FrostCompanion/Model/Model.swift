//
//  Model.swift
//  FrostCompanion
//
//  Created by pacu on 2024-08-21.
//

import Foundation

struct TrustedDealerScheme {
    let config: FROSTSchemeConfig
    let shares: [String : JSONKeyShare]
    let publicKeyPackage: JSONPublicKeyPackage
}

struct JSONPublicKeyPackage: Equatable {
    let raw: String
}

struct JSONKeyShare: Equatable {
    let raw: String
}

extension JSONKeyShare {
    static let empty = JSONKeyShare(
        raw: ""
    )
    static let mock = JSONKeyShare(
        raw:
                """
                {
                    "header": {
                        "version": 0,
                        "ciphersuite": "FROST(Pallas, BLAKE2b-512)"
                    },
                    "identifier": "0100000000000000000000000000000000000000000000000000000000000000",
                    "signing_share": "b02e5a1e43a7f305177682574ac63c1a5f7f57db644c992635d09f699e56f41e",
                    "commitment": [
                        "4141ac3d66ff87c4d14eb14f4262b69de15f7093dfd1f411a02ea70644f0d41f",
                        "2eb4cd3ace283ba6bb9058ff08d0561ff6d87057ecc87b0701123979291fb082"
                    ]
                }
                """
    )
}


struct FROSTSchemeConfig {
    let maxParticipants: Int
    let minParticipants: Int

    fileprivate init(
        uncheckedMax: Int,
        uncheckedMin: Int
    ) {
        self.maxParticipants = uncheckedMax
        self.minParticipants = uncheckedMin
    }

    init(
        maxParticipants: Int,
        minParticipants: Int
    ) throws {
        guard maxParticipants > minParticipants, minParticipants > 2 else {
            throw AppErrors.invalidConfiguration
        }
        self.maxParticipants = maxParticipants
        self.minParticipants = minParticipants
    }
}


extension FROSTSchemeConfig {
    static let twoOfThree = FROSTSchemeConfig(
        uncheckedMax: 3,
        uncheckedMin: 2
    )
}


extension JSONPublicKeyPackage {
    static let mock = JSONPublicKeyPackage(raw: """
            {
                "header": {
                    "version": 0,
                    "ciphersuite": "FROST(Pallas, BLAKE2b-512)"
                },
                "verifying_shares": {
                    "0100000000000000000000000000000000000000000000000000000000000000": "35a83b6ce26fd8812e7e100ff0f9557dd873080478272770745d35c2c1698fad",
                    "0200000000000000000000000000000000000000000000000000000000000000": "a2e91b0636456d78b4830f4c926d07638dcfa41083071ab94b87dd8d9ea22f26",
                    "0300000000000000000000000000000000000000000000000000000000000000": "cdca48566dd4dc57a9cd546b1ad64212eb3d53eba9c852c1a1d6f661d08d67b2"
                },
                "verifying_key": "4141ac3d66ff87c4d14eb14f4262b69de15f7093dfd1f411a02ea70644f0d41f"
            }
            """)
}

extension TrustedDealerScheme {
    static let mock = TrustedDealerScheme(
        config: .twoOfThree,
        shares: Self.mockShares,
        publicKeyPackage: JSONPublicKeyPackage.mock
    )

    static let mockShares = [
        "0100000000000000000000000000000000000000000000000000000000000000" : JSONKeyShare(
            raw: """
                                {
                                    "header": {
                                        "version": 0,
                                        "ciphersuite": "FROST(Pallas, BLAKE2b-512)"
                                    },
                                    "identifier": "0100000000000000000000000000000000000000000000000000000000000000",
                                    "signing_share": "b02e5a1e43a7f305177682574ac63c1a5f7f57db644c992635d09f699e56f41e",
                                    "commitment": [
                                        "4141ac3d66ff87c4d14eb14f4262b69de15f7093dfd1f411a02ea70644f0d41f",
                                        "2eb4cd3ace283ba6bb9058ff08d0561ff6d87057ecc87b0701123979291fb082"
                                    ]
                                }
                                """
        ),
        "0200000000000000000000000000000000000000000000000000000000000000" : JSONKeyShare(
            raw: """
                                {
                                    "header": {
                                        "version": 0,
                                        "ciphersuite": "FROST(Pallas, BLAKE2b-512)"
                                    },
                                    "identifier": "0200000000000000000000000000000000000000000000000000000000000000",
                                    "signing_share": "850da1fd0b6f609b60a0f81d0aa79986e46cee490f837a5ccf349ac9b904790b",
                                    "commitment": [
                                        "4141ac3d66ff87c4d14eb14f4262b69de15f7093dfd1f411a02ea70644f0d41f",
                                        "2eb4cd3ace283ba6bb9058ff08d0561ff6d87057ecc87b0701123979291fb082"
                                    ]
                                }
                                """
        ),
        "0300000000000000000000000000000000000000000000000000000000000000" : JSONKeyShare(
            raw: """
                    {
                        "header": {
                            "version": 0,
                            "ciphersuite": "FROST(Pallas, BLAKE2b-512)"
                        },
                        "identifier": "",
                        "signing_share": "5bece7dcf52114bd877303eec5203d156a5a85b8b9b95b9269999429d5b2fd37",
                        "commitment": [
                            "4141ac3d66ff87c4d14eb14f4262b69de15f7093dfd1f411a02ea70644f0d41f",
                            "2eb4cd3ace283ba6bb9058ff08d0561ff6d87057ecc87b0701123979291fb082"
                        ]
                    }
                    """
        )
    ]
}
