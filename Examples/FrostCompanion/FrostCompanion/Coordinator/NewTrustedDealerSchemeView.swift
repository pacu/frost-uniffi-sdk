//
//  NewTrustedDealerSchemeView.swift
//  FrostCompanion
//
//  Created by Pacu in  2024.
//    
   

import SwiftUI
import ComposableArchitecture

struct NewTrustedDealerSchemeView: View {
    static let intFormater: NumberFormatter = {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.allowsFloats = false
        formatter.maximumFractionDigits = 0
        return formatter
    }()

    @Bindable var store: StoreOf<TrustedDealerFeature>
    @FocusState var focus: TrustedDealerFeature.State.Field?
    var body: some View {
        Form {
            Section {
                TextField("Min Participants", value: $store.minParticipants, format: .number)
                    .focused($focus, equals: .minParticipants)
                TextField("Max Participants", value: $store.maxParticipants, formatter: Self.intFormater)
                    .focused($focus, equals: .minParticipants)
                Button("create scheme") {
                    store.send(.createSchemePressed)
                }
            }
            .bind($store.focus, to: $focus)
        }
        .padding()
    }
}

#Preview {
    NewTrustedDealerSchemeView(store: Store(initialState: TrustedDealerFeature.State(), reducer: {
        TrustedDealerFeature()
    }))
}
