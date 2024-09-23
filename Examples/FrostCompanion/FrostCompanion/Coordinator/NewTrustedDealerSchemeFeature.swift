//
//  NewTrustedDealerSchemeFeature.swift
//  FrostCompanion
//
//  Created by Pacu in  2024.
//    
   

import Foundation
import ComposableArchitecture

@Reducer
struct NewTrustedDealerSchemeFeature {
    @ObservableState
    struct State {
        let schemeConfig: FROSTSchemeConfig
        var scheme: TrustedDealerScheme?
//        var path: StackState<
    }

    enum Action {
        case dealerSucceeded(TrustedDealerScheme)
        case dealerFailed(AppErrors)
    }
}

