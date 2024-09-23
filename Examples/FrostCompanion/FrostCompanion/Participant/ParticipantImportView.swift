//
//  ParticipantImportView.swift
//  FrostCompanion
//
//  Created by pacu on 2024-08-21
//

import SwiftUI
import ComposableArchitecture

struct ParticipantImportView: View {
    @Bindable var store: StoreOf<ParticipantImportFeature>
    var body: some View {
        Form {
            Text("Paste your key-package.json contents")
            TextEditor(text: $store.keyShare.raw.sending(
                \.setKeyShare
            ))
            

            Button(
                "Import"
            ) {
                store.send(
                    .importButtonTapped
                )
            }
        }
        .navigationTitle(
            "Import your Key-package JSON"
        )
    }
}

#Preview {
    ParticipantImportView(store: Store(
        initialState: ParticipantImportFeature.State(
            keyShare: JSONKeyShare.mock
        )
    ) {
        ParticipantImportFeature()
    }
    )
    .padding()
}
