//
//  PublicKeyPackageFeature.swift
//  FrostCompanion
//
//  Created by Pacu in  2024.
//    
   

import Foundation
import ComposableArchitecture

@Reducer
struct PublicKeyPackageFeature {
    @ObservableState
    struct State {
        let package: JSONPublicKeyPackage
    }

}

