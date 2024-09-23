//
//  PublicKeyPackageDetail.swift
//  FrostCompanion
//
//  Created by Pacu in  2024.
//    
   

import SwiftUI
import ComposableArchitecture
struct PublicKeyPackageDetail: View {
    let store: StoreOf<PublicKeyPackageFeature>
    var body: some View {
        Text(store.package.raw)
            .multilineTextAlignment(/*@START_MENU_TOKEN@*/.leading/*@END_MENU_TOKEN@*/)
            .padding()
            .navigationTitle("Public Key Package")
            .toolbar {
                Button(action: /*@START_MENU_TOKEN@*/{}/*@END_MENU_TOKEN@*/, label: {
                    Image(systemName: "square.and.arrow.up")
                })
            }
    }
}

#Preview {
    NavigationStack {
        PublicKeyPackageDetail(
            store: Store(initialState: PublicKeyPackageFeature.State(
                package: .mock
            ),
                         reducer: {
                             PublicKeyPackageFeature()
                         })
        )
    }
}
