//
//  ParticipantReducer.swift
//  FrostCompanion
//
//  Created by pacu on 2024-08-21.
//

import Foundation
import ComposableArchitecture

@Reducer
struct ParticipantImportFeature {
    @ObservableState
    struct State: Equatable {
        var keyShare: JSONKeyShare = .empty
    }
    
    enum Action {
        case cancelButtonTapped
        case delegate(Delegate)
        case importButtonTapped
        case setKeyShare(String)
        enum Delegate: Equatable {
            case cancel
            case keyShareImported(JSONKeyShare)
        }
    }
    
    @Dependency(\.dismiss) var dismiss
    
    var body: some ReducerOf<Self> {
        Reduce { state, action  in
            switch action {
            case .cancelButtonTapped:
                return .run { _ in await self.dismiss() }
            case .delegate:
                return .none
            case .importButtonTapped:
                return .run { [share = state.keyShare] send in
                    await send(.delegate(.keyShareImported(share)))
                    await self.dismiss()
                }
            case .setKeyShare(let keyShare):
                state.keyShare = JSONKeyShare(raw: keyShare)
                return .none
//            case .importSuccess:
//
//            case .importFailure:
//                return .none
            }
            
        }
    }
}
