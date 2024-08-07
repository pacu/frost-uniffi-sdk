//
//  OrchardSwiftTests.swift
//  
//
//  Created by Pacu in  2024.
//    
   

import XCTest
import Foundation
import SwiftRadix
@testable import OrchardSwiftFFI
final class OrchardSwiftTests: XCTestCase {
    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        // Any test you write for XCTest can be annotated as throws and async.
        // Mark your test throws to produce an unexpected failure when your test encounters an uncaught error.
        // Mark your test async to allow awaiting for asynchronous code to complete. Check the results with assertions afterwards.

        let hexAk = "d2bf40ca860fb97e9d6d15d7d25e4f17d2e8ba5dd7069188cbf30b023910a71b".hex!.bytes
        let ak = try OrchardSpendValidatingKey.fromBytes(bytes: Data(hexAk))

        let randomSeedBytes = "659ce2e5362b515f30c38807942a10c18a3a2f7584e7135b3523d5e72bb796cc64c366a8a6bfb54a5b32c41720bdb135758c1afacac3e72fd5974be0846bf7a5".hex!.bytes

        let zcashNetwork = ZcashNetwork.testnet

        let fvk = try OrchardFullViewingKey.newFromValidatingKeyAndSeed(
            validatingKey: ak,
            zip32Seed: Data(randomSeedBytes),
            network: zcashNetwork
        )


        let address = try fvk.deriveAddress()

        

    }
}
