// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "IOSSecureKit",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "IOSSecureKit",
            targets: ["IOSSecureKit"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.9.0")
    ],
    targets: [
        .target(
            name: "IOSSecureKit",
            dependencies: ["Alamofire"]
        ),
        .testTarget(
            name: "IOSSecureKitTests",
            dependencies: ["IOSSecureKit"]
        ),
    ]
)
