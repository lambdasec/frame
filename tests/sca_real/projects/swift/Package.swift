// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "FrameFixture",
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-collections.git", exact: "1.0.6"),
    ],
    targets: [
        .target(name: "FrameFixture", dependencies: [
            .product(name: "ArgumentParser", package: "swift-argument-parser"),
            .product(name: "Collections", package: "swift-collections"),
        ]),
    ]
)
