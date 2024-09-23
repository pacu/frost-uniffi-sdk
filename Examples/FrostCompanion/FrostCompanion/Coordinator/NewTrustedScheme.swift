//
//  NewTrustedScheme.swift
//  FrostCompanion
//
//  Created by Pacu in  2024.
//


import SwiftUI
import ComposableArchitecture
struct NewTrustedScheme: View {
    @Bindable var store: StoreOf<NewTrustedDealerSchemeFeature>
    var body: some View {

        if let scheme = store.scheme {
            List {
                ForEach(scheme.shares.keys.sorted(), id: \.self) { identifier in
                    NavigationLink(state: ParticipantDetailFeature.State(keyShare: scheme.shares[identifier]!)){
                        Text(identifier)
                    }

                }
                NavigationLink(state: PublicKeyPackageFeature.State(package: scheme.publicKeyPackage)) {

                    Text("Public Key Package")
                }

            }
            .navigationTitle("Participants")
        } else {
            Text("❄️ FROSTING... ❄️")
        }


    }
}

#Preview {
    NewTrustedScheme(
        store:  Store(initialState: NewTrustedDealerSchemeFeature.State(
            schemeConfig: FROSTSchemeConfig.twoOfThree,
            scheme: TrustedDealerScheme.mock
        ),
                      reducer: {
                          NewTrustedDealerSchemeFeature()
                      })
    )
}
