#!/bin/sh
sed -i 's|^[[:space:]]*\.binaryTarget(name: "RustFramework", url: "https://github.com/pacu/frost-uniffi-sdk/releases/download/[^"]+/RustFramework.xcframework.zip", checksum: "[^"]+"\),|        .binaryTarget(name: "RustFramework", path: "FrostSwift/RustFramework.xcframework.zip"),|' Package.swift