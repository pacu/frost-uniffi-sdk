//
//  FrostCompanionTests.swift
//  FrostCompanionTests
//
//  Created by Pacu on 2024-06-03.
//

import XCTest
import ComposableArchitecture
@testable import FrostCompanion
final class FrostCompanionTests: XCTestCase {
    @MainActor
    func testParticipantModifiesMainState() async {
        let store = TestStore(initialState: MainScreenFeature.State()) {
            MainScreenFeature()
        }

        await store.send(.participantTapped) {
            $0.destination = .participant(ParticipantImportFeature.State(
                keyShare: JSONKeyShare.empty
            ))
        }
    }
}
