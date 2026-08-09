// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "AIZenflowQualityControl",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "QualityCore", targets: ["QualityCore"]),
        .executable(name: "quality", targets: ["QualityCLI"])
    ],
    targets: [
        .target(
            name: "QualityCore",
            path: "engine/Sources/QualityCore"
        ),
        .executableTarget(
            name: "QualityCLI",
            dependencies: ["QualityCore"],
            path: "engine/Sources/QualityCLI",
            plugins: ["EngineBuildProvenancePlugin"]
        ),
        .executableTarget(
            name: "EngineBuildProvenanceGenerator",
            path: "tools/EngineBuildProvenanceGenerator"
        ),
        .plugin(
            name: "EngineBuildProvenancePlugin",
            capability: .buildTool(),
            dependencies: ["EngineBuildProvenanceGenerator"]
        ),
        .testTarget(
            name: "QualityCoreTests",
            dependencies: ["QualityCore"],
            path: "tests/QualityCoreTests"
        )
    ]
)
