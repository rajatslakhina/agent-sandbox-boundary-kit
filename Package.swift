// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AgentSandbox",
    // Only the platforms CI actually builds: macOS (swift build + swift test) and iOS (xcodebuild, Simulator SDK).
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "AgentSandbox", targets: ["AgentSandbox"]),
    ],
    targets: [
        .target(name: "AgentSandbox"),
        .testTarget(name: "AgentSandboxTests", dependencies: ["AgentSandbox"]),
    ]
)
