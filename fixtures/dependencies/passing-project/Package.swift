// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DependencyFixture",
    platforms: [.macOS(.v13)],
    products: [.library(name: "DependencyFixture", targets: ["DependencyFixture"])],
    dependencies: [
        .package(url: "https://github.com/example/fixture-package.git", from: "1.0.0")
    ],
    targets: [.target(name: "DependencyFixture")]
)
