//
//  MainScreenReducer.swift
//  FrostCompanion
//
//  Created by pacu on 21/08/2024.
//

import Foundation
import ComposableArchitecture


@Reducer
struct MainScreenFeature {
    

    @ObservableState
    struct State: Equatable {
        @Presents var destination: Destination.State?

    }
    
    enum Action {
    }
    
//        .ifLet(\.$destination, action: \.destination) {
//            Destination.participant(ParticipantReducer())
//        }
//        .forEach(\.path, action: \.path)  {
//            Path()
//        }
    
}


extension MainScreenFeature {

    @Reducer(state: .equatable)
    enum Destination {
        case participant(ParticipantImportFeature)
    }
}
