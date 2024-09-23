//
//  AppView.swift
//  FrostCompanion
//
//  Created by Pacu in  2024.
//    
   

import SwiftUI
import ComposableArchitecture
struct AppView: View {
    @Bindable var store: StoreOf<AppFeature>
    var body: some View {
        NavigationStack(
            path: $store.scope(state: \.path, action: \.path)
        ) {
            MainScreenView(
                store:
                    store.scope(
                        state: \.mainScreen,
                        action: \.mainScreen
                    )
            )
        } destination: { store in
            switch store.case {
            case let .importParticipant(importStore):
                ParticipantImportView(store: importStore)
            case let .coordinator(trustedDealerStore):
                NewTrustedDealerSchemeView(store: trustedDealerStore)
            case let .newTrustedDealerScheme(newTrustedDealerScheme):
                NewTrustedDealerSchemeFeature()
            }
        }
    }
}

#Preview {
    AppView(store: Store(
        initialState: AppFeature.State()
    ){
        AppFeature()
    }
    )
}
