//
//  ContentView.swift
//  FrostCompanion
//
//  Created by Pacu on 2024-06-03.
//

import SwiftUI
import ComposableArchitecture
struct MainScreenView: View {
    @Bindable var store: StoreOf<MainScreenFeature>
    var body: some View {
            VStack {
                Image(systemName: "snow")
                    .imageScale(.large)
                    .foregroundStyle(.tint)
                
                Text("Who are you?")
                VStack {
                    NavigationLink(state: AppFeature.Path.State.importParticipant(.init())){
                        Text("Participant")
                    }

                    NavigationLink(state: AppFeature.Path.State.coordinator(.init())) {
                        Text("Coordinator")
                    }
                }
            }
            .padding()

        .navigationTitle("Hello, FROST! ❄️")
    }

}

#Preview {
    MainScreenView(
        store: Store(initialState: MainScreenFeature.State()){
            MainScreenFeature()
        }
    )
}
