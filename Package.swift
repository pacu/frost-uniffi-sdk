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
        ),
        .library(
            name: "OrchardSwiftFFI",
            targets: ["OrchardSwiftFFI"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/orchetect/SwiftRadix", from: "1.3.0")
    ],
    targets: [
        .target(
            name: "FrostSwift",
            dependencies: [
                .target(name: "FrostSwiftFFI")
            ], path: "FrostSwift/Sources/FrostSwift"
        ),
        .binaryTarget(name: "RustFramework", url: "https://github.com/pacu/frost-uniffi-sdk/releases/download/0.0.6/RustFramework.xcframework.zip", checksum: "b84677041219487bca551d563ff2993164454e6d70fd74076ed1f6309a7c9d85"),
        .target(
            name: "FrostSwiftFFI",
            dependencies: [
                .target(name: "RustFramework")
            ], path: "FrostSwift/Sources/FrostSwiftFFI"
        ),
        .testTarget(
            name: "NotRedPallasTests",
            dependencies: [
                "FrostSwiftFFI",
            ],
            path: "FrostSwift/Tests/FrostSwiftFFI"
        ),
        .testTarget(
            name: "FrostTests",
            dependencies: ["FrostSwift"],
            path: "FrostSwift/Tests/FrostSwift"
        ),
        .testTarget(
            name: "OrchardSwiftFFITests",
            dependencies: [
                "FrostSwiftFFI",
                "SwiftRadix"
            ],
            path: "FrostSwift/Tests/OrchardSwiftFFI"
        )
    ]
)
