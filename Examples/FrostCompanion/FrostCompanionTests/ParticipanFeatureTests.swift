//
//  ParticipanFeatureTests.swift
//  FrostCompanionTests
//
//  Created by Pacu in  2024.
//    
   

import XCTest
import ComposableArchitecture
@testable import FrostCompanion

final class ParticipanFeatureTests: XCTestCase {
    @MainActor
    func testTextFieldInputInvalidInputDoesNotChangeState() async {
        let store = TestStore(initialState: ParticipantImportFeature.State()) {
            ParticipantImportFeature()
        }

        await store.send(.setKeyShare("Hello test")) {
            $0.keyShare = JSONKeyShare.empty
        }
    }
}
