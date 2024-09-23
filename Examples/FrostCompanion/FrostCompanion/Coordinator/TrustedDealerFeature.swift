//
//  TrustedDealerFeature.swift
//  FrostCompanion
//
//  Created by Pacu in  2024.
//    
   

import Foundation
import ComposableArchitecture

@Reducer
struct TrustedDealerFeature {
    @ObservableState
    struct State: Equatable {
        var maxParticipants: Int = 3
        var minParticipants: Int = 2

        var focus: Field? = .minParticipants

        enum Field: Hashable {
            case minParticipants
            case maxParticipants
        }
    }

    enum Action: BindableAction, Equatable {
        case binding(BindingAction<State>)
        case createSchemePressed
    }

    var body: some ReducerOf<Self> {
        BindingReducer()
        Reduce { state, action  in
            switch action {
            case .binding:
                return .none
            case .createSchemePressed:
                return .none
            }
        }
    }
}
