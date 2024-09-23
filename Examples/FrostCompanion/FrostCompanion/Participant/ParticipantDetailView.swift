//
//  ParticipantDetailView.swift
//  FrostCompanion
//
//  Created by Pacu in  2024.
//    
   

import SwiftUI
import ComposableArchitecture
struct ParticipantDetailView: View {

    @Bindable var store: StoreOf<ParticipantDetailFeature>
    var body: some View {
        Text(verbatim: store.keyShare.raw)
            .navigationTitle("Participant Detail")
            .toolbar {
                ToolbarItem {
                    Button(action: /*@START_MENU_TOKEN@*/{}/*@END_MENU_TOKEN@*/, label: {
                        Image(systemName: "trash")
                                         .foregroundColor(.red)
                    })
                }
            }
    }
}

#Preview {
    NavigationStack {
        ParticipantDetailView(store: Store(
            initialState: ParticipantDetailFeature.State(
                keyShare: JSONKeyShare.mock
            )
        ) {
            ParticipantDetailFeature()
        })
    }
}
