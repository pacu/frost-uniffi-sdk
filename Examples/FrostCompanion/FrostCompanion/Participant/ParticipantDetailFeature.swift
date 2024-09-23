//
//  ParticipantDetail.swift
//  FrostCompanion
//
//  Created by Pacu in  2024.
//    
   

import Foundation
import ComposableArchitecture

@Reducer
struct ParticipantDetailFeature {
    @ObservableState
    struct State: Equatable {
        let keyShare: JSONKeyShare
    }
    enum Action {

    }

    var body: some ReducerOf<Self> {
        Reduce { state, action in
            switch action {

            }
        }
    }
}
