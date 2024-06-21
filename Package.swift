// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.
// Swift Package: FrostSwiftFFI

import PackageDescription;

let package = Package(
    name: "FrostSwiftFFI",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "FrostSwiftFFI",
            targets: ["FrostSwiftFFI"]
        )
    ],
    dependencies: [ ],
    targets: [
        .target(
            name: "FrostSwift",
            dependencies: [
                .target(name: "FrostSwiftFFI")
            ], path: "FrostSwift/Sources/FrostSwift"
        ),
        .binaryTarget(name: "RustFramework", url: "https://github.com/pacu/frost-uniffi-sdk/releases/download/0.0.3/RustFramework.xcframework.zip", checksum: "a0be9857902e6d5f70150a4d771def344289dd521c09ee894300ac154db4f7fd"),
        .target(
            name: "FrostSwiftFFI",
            dependencies: [
                .target(name: "RustFramework")
            ], path: "FrostSwift/Sources/FrostSwiftFFI"
        ),
        .testTarget(
            name: "NotRedPallasTests",
            dependencies: ["FrostSwiftFFI"],
            path: "FrostSwift/Tests/FrostSwiftFFI"
        ),
        .testTarget(
            name: "FrostTests",
            dependencies: ["FrostSwift"],
            path: "FrostSwift/Tests/FrostSwift"
        )
    ]
)
