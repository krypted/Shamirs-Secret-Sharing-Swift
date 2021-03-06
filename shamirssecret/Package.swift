// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ShamirsSecret",
    products: [
        .executable(name: "shamirssecret", targets: ["ShamirsSecret"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.0.0"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
        .package(url: "https://github.com/RNCryptor/RNCryptor.git", .upToNextMajor(from: "5.0.0")),
        .package(name: "CryptorECC", url: "https://github.com/IBM-Swift/BlueECC.git", from: "1.2.4")

        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "ShamirsSecret",
            dependencies: [
                .product(name: "CryptorECC", package: "CryptorECC"),
                .product(name: "RNCryptor", package: "RNCryptor"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "BigInt", package: "BigInt"),
            ]),
        .testTarget(
            name: "ShamirsSecretTests",
            dependencies: ["ShamirsSecret"]),
    ]
)
