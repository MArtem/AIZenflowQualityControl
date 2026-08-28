import Foundation
import Testing
@testable import QualityCore

@Suite("Xcode build-log source membership")
struct XcodeBuildLogMembershipTests {
    @Test("Compiler sources are captured in deterministic repository order")
    func capturesCompilerSources() throws {
        let log = try buildLog(
            command: "/usr/bin/swiftc -frontend -c /repository/Sources/B.swift /repository/Sources/A.swift"
        )

        let observation = try XcodeBuildLogMembershipExtractor.extract(
            logData: log,
            repositoryRoot: repositoryRoot,
            sourcePaths: ["Sources"]
        )

        #expect(observation.compiledSourcePaths == ["Sources/A.swift", "Sources/B.swift"])
        #expect(observation.compilerSectionCount == 1)
        #expect(observation.buildLogSHA256.count == 64)
    }

    @Test("Non-source paths in compiler commands are not source-membership inputs")
    func ignoresNonSourceCompilerPaths() throws {
        let log = try buildLog(
            command: "/usr/bin/swiftc -frontend -c /repository/Sources/App.swift /repository/App.xcodeproj /repository/build/App.o",
            location: "file:///repository/App.xcodeproj"
        )

        let observation = try XcodeBuildLogMembershipExtractor.extract(
            logData: log,
            repositoryRoot: repositoryRoot,
            sourcePaths: ["Sources"]
        )

        #expect(observation.compiledSourcePaths == ["Sources/App.swift"])
    }

    @Test("A compiled repository source outside the declared scope is rejected")
    func rejectsUncoveredRepositorySource() throws {
        expectError(.uncoveredRepositoryInputs(["Other/Hidden.swift"])) {
            _ = try XcodeBuildLogMembershipExtractor.extract(
                logData: try buildLog(
                    command: "/usr/bin/swiftc -frontend -c /repository/Other/Hidden.swift"
                ),
                repositoryRoot: repositoryRoot,
                sourcePaths: ["Sources"]
            )
        }
    }

    @Test("Compiler response lists block membership proof until expanded safely")
    func rejectsIndirectCompilerInputList() throws {
        expectError(.unresolvedCompilerInputList) {
            _ = try XcodeBuildLogMembershipExtractor.extract(
                logData: try buildLog(
                    command: "/usr/bin/swiftc -frontend -c @/repository/Inputs.SwiftFileList"
                ),
                repositoryRoot: repositoryRoot,
                sourcePaths: ["Sources"]
            )
        }
    }

    @Test("Xcode Swift driver wrappers defer to structured per-source compiler sections")
    func structuredSwiftCompileSuppliesMembership() throws {
        let log = try JSONSerialization.data(
            withJSONObject: [
                "commandInvocationDetails": [
                    "commandDetails": "builtin-SwiftDriver -- /usr/bin/swiftc @/derived/App.SwiftFileList"
                ],
                "messages": [],
                "subsections": [
                    [
                        "commandInvocationDetails": [
                            "commandDetails": "SwiftCompile normal arm64 Compiling\\ App.swift /repository/Sources/App.swift"
                        ],
                        "location": ["url": "file:///repository/Sources/App.swift"],
                        "messages": [],
                        "subsections": []
                    ]
                ]
            ],
            options: [.sortedKeys]
        )

        let observation = try XcodeBuildLogMembershipExtractor.extract(
            logData: log,
            repositoryRoot: repositoryRoot,
            sourcePaths: ["Sources"]
        )

        #expect(observation.compiledSourcePaths == ["Sources/App.swift"])
        #expect(observation.compilerSectionCount == 1)
    }

    @Test("Linker response files do not block source membership proof")
    func linkerResponseFileDoesNotBlockMembership() throws {
        let log = try JSONSerialization.data(
            withJSONObject: [
                "commandInvocationDetails": [
                    "commandDetails": "Ld /derived/App /usr/bin/clang @/derived/linker-args.resp"
                ],
                "messages": [],
                "subsections": [
                    [
                        "commandInvocationDetails": [
                            "commandDetails": "SwiftCompile normal arm64 Compiling\\ App.swift /repository/Sources/App.swift"
                        ],
                        "location": ["url": "file:///repository/Sources/App.swift"],
                        "messages": [],
                        "subsections": []
                    ]
                ]
            ],
            options: [.sortedKeys]
        )

        let observation = try XcodeBuildLogMembershipExtractor.extract(
            logData: log,
            repositoryRoot: repositoryRoot,
            sourcePaths: ["Sources"]
        )

        #expect(observation.compiledSourcePaths == ["Sources/App.swift"])
        #expect(observation.compilerSectionCount == 1)
    }

    @Test("Relative compiler source paths block membership proof")
    func rejectsRelativeCompilerSourcePath() throws {
        expectError(.unresolvedCompilerInputPath) {
            _ = try XcodeBuildLogMembershipExtractor.extract(
                logData: try buildLog(
                    command: "/usr/bin/swiftc -frontend -c Sources/App.swift"
                ),
                repositoryRoot: repositoryRoot,
                sourcePaths: ["Sources"]
            )
        }
    }

    @Test("A repository source symlink escaping the root is rejected")
    func rejectsEscapingSourceSymlink() throws {
        let fixture = try TemporaryProfile(data: Data("{}".utf8))
        defer {
            do {
                try fixture.remove()
            } catch {
                Issue.record("Fixture cleanup failed: \(error)")
            }
        }
        try fixture.createSymbolicLink(at: "Sources/Escaped.swift", destination: "/etc/hosts")

        expectError(.repositoryPathEscapesRoot) {
            _ = try XcodeBuildLogMembershipExtractor.extract(
                logData: try buildLog(
                    command: "/usr/bin/swiftc -frontend -c \(fixture.directory.path)/Sources/Escaped.swift"
                ),
                repositoryRoot: fixture.directory,
                sourcePaths: ["Sources"]
            )
        }
    }

    private var repositoryRoot: URL {
        URL(fileURLWithPath: "/repository", isDirectory: true)
    }

    private func buildLog(command: String, location: String? = nil) throws -> Data {
        var root: [String: Any] = [
            "commandInvocationDetails": ["commandDetails": command],
            "messages": [],
            "subsections": []
        ]
        if let location {
            root["location"] = ["url": location]
        }
        return try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
    }

    private func expectError(
        _ expected: XcodeBuildLogMembershipError,
        operation: () throws -> Void
    ) {
        do {
            try operation()
            Issue.record("Expected XcodeBuildLogMembershipError.\(expected)")
        } catch let error as XcodeBuildLogMembershipError {
            #expect(error == expected)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }
}
