//
//  AppFeature.swift
//  FrostCompanion
//
//  Created by Pacu in  2024.
//


import Foundation
import ComposableArchitecture
@Reducer
struct AppFeature {
    @ObservableState
    struct State: Equatable {
        var path = StackState<Path.State>()
        var mainScreen = MainScreenFeature.State()
    }

    enum Action {
        case path(StackActionOf<Path>)
        case mainScreen(MainScreenFeature.Action)
    }

    @Reducer(state: .equatable)
    enum Path {
        case importParticipant(ParticipantImportFeature)
        case coordinator(TrustedDealerFeature)
        case newTrustedDealerScheme(NewTrustedScheme)
    }

    var body: some ReducerOf<Self> {
        Scope(state: \.mainScreen, action: \.mainScreen) {
            MainScreenFeature()
        }
        Reduce { state, action in
            switch action {
//            case .path(.element(_, .coordinator(.)))
            case .path:
                return .none

            case .mainScreen:
                return .none
            }
        }
        .forEach(\.path, action: \.path)
    }
}
