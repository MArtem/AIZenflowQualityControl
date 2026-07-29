import Foundation
import Testing
@testable import QualityCore

@Suite("Path and symbolic-link verifier boundaries")
struct PathBoundaryTests {
    @Test("A failed repeated fixture write preserves the existing entry")
    func repeatedFixtureWritePreservesExistingEntry() throws {
        let profile = try makeProfile()
        defer { expectSuccessfulRemoval(of: profile) }
        let original = Data("original".utf8)
        let relativePath = "repository/existing.txt"
        try profile.write(original, at: relativePath)

        #expect(throws: Error.self) {
            try profile.write(Data("replacement".utf8), at: relativePath)
        }

        let existingURL = profile.directory.appendingPathComponent(
            relativePath,
            isDirectory: false
        )
        #expect(try Data(contentsOf: existingURL) == original)
    }

    @Test("Lexical traversal in project and source paths never passes")
    func lexicalTraversalFails() {
        let report = QualityCommands.validateProfile(at: invalidTraversalProfileURL)

        #expect(report.status.rawValue == QualityStatus.fail.rawValue)
        #expect(
            report.checks.filter { $0.id == "QC.PROFILE.PATH_TRAVERSAL" }.count == 2
        )
        #expect(report.checks.allSatisfy { $0.status.rawValue != QualityStatus.pass.rawValue })
    }

    @Test("Doctor rejects a project directory that resolves outside the repository")
    func doctorRejectsProjectSymlinkEscape() throws {
        let profile = try makeProfile(projectPath: "Escaped.xcodeproj")
        defer { expectSuccessfulRemoval(of: profile) }
        try prepareSafeFixture(profile)
        try profile.write(
            Data("// External project marker".utf8),
            at: "outside/External.xcodeproj/project.pbxproj"
        )
        try profile.createSymbolicLink(
            at: "repository/Escaped.xcodeproj",
            destination: "../outside/External.xcodeproj"
        )

        let report = QualityCommands.doctor(
            profileURL: profile.url,
            repositoryRoot: repositoryURL(for: profile)
        )

        #expect(report.status.rawValue == QualityStatus.fail.rawValue)
        #expect(
            report.checks.contains {
                $0.id == "QC.DOCTOR.PROJECT_BOUNDARY"
                    && $0.status.rawValue == QualityStatus.fail.rawValue
            }
        )
    }

    @Test("Doctor rejects a source directory that resolves outside the repository")
    func doctorRejectsSourceSymlinkEscape() throws {
        let profile = try makeProfile(sourcePaths: ["EscapedSources"])
        defer { expectSuccessfulRemoval(of: profile) }
        try prepareSafeFixture(profile)
        try prepareEscapedSourceFixture(profile)

        let report = QualityCommands.doctor(
            profileURL: profile.url,
            repositoryRoot: repositoryURL(for: profile)
        )

        #expect(report.status.rawValue == QualityStatus.fail.rawValue)
        #expect(
            report.checks.contains {
                $0.id == "QC.DOCTOR.SOURCE_BOUNDARY"
                    && $0.status.rawValue == QualityStatus.fail.rawValue
            }
        )
    }

    @Test("Static scan rejects a source root that resolves outside the repository")
    func staticScanRejectsSourceSymlinkEscape() throws {
        let profile = try makeProfile(sourcePaths: ["EscapedSources"])
        defer { expectSuccessfulRemoval(of: profile) }
        try prepareSafeFixture(profile)
        try prepareEscapedSourceFixture(profile)

        let report = QualityCommands.staticScan(
            profileURL: profile.url,
            policyURL: staticPolicyURL,
            repositoryRoot: repositoryURL(for: profile)
        )

        #expect(report.status.rawValue == QualityStatus.fail.rawValue)
        #expect(
            report.checks.contains {
                $0.id == "QC.STATIC.SOURCE_BOUNDARY"
                    && $0.status.rawValue == QualityStatus.fail.rawValue
            }
        )
        #expect(!report.checks.contains { $0.id == "QC.STATIC.SCAN" })
    }

    @Test("Static scan blocks a symbolic-link entry without following its target")
    func staticScanBlocksNestedSymlink() throws {
        let profile = try makeProfile()
        defer { expectSuccessfulRemoval(of: profile) }
        try prepareSafeFixture(profile)
        try profile.write(
            Data("struct ExternalFixture {}".utf8),
            at: "outside/External.swift"
        )
        try profile.createSymbolicLink(
            at: "repository/Sources/Escaped.swift",
            destination: "../../outside/External.swift"
        )

        let report = QualityCommands.staticScan(
            profileURL: profile.url,
            policyURL: staticPolicyURL,
            repositoryRoot: repositoryURL(for: profile)
        )

        #expect(report.status.rawValue == QualityStatus.blocked.rawValue)
        #expect(
            report.checks.contains {
                $0.id == "QC.STATIC.SYMLINK_REQUIRES_REVIEW"
                    && $0.status.rawValue == QualityStatus.blocked.rawValue
                    && $0.path == "Sources/Escaped.swift"
            }
        )
        #expect(!report.checks.contains { $0.id == "QC.STATIC.SCAN" })
    }

    @Test("Doctor rejects a sandbox cache that resolves outside its sandbox root")
    func doctorRejectsSandboxCacheSymlinkEscape() throws {
        let profile = try makeProfile(sandboxCacheRelativePath: "sandbox/escaped-cache")
        defer { expectSuccessfulRemoval(of: profile) }
        try prepareSafeFixture(profile)
        try profile.write(Data("outside cache".utf8), at: "outside/cache/.keep")
        try profile.createSymbolicLink(
            at: "sandbox/escaped-cache",
            destination: "../outside/cache"
        )

        let report = QualityCommands.doctor(
            profileURL: profile.url,
            repositoryRoot: repositoryURL(for: profile)
        )

        #expect(report.status.rawValue == QualityStatus.fail.rawValue)
        #expect(
            report.checks.contains {
                $0.id == "QC.DOCTOR.SANDBOX_CACHE_BOUNDARY"
                    && $0.status.rawValue == QualityStatus.fail.rawValue
            }
        )
    }

    private func makeProfile(
        projectPath: String = "Safe.xcodeproj",
        sourcePaths: [String] = ["Sources"],
        sandboxCacheRelativePath: String = "sandbox/cache"
    ) throws -> TemporaryProfile {
        try TemporaryProfile(dataProvider: { directory in
            let sandboxRoot = directory.appendingPathComponent("sandbox", isDirectory: true)
            let sandboxCache = directory.appendingPathComponent(
                sandboxCacheRelativePath,
                isDirectory: true
            )
            let profile: [String: Any] = [
                "schemaVersion": 1,
                "project": ["kind": "xcodeproj", "path": projectPath],
                "scheme": "BoundaryFixture",
                "sourcePaths": sourcePaths,
                "mode": "controlled",
                "permissions": [
                    "testCreation": "ask",
                    "testModification": "ask",
                    "localTestExecution": "ask",
                    "githubExecution": "manual",
                    "uiTests": "ask",
                    "simulatorOrDevice": "ask",
                    "performanceOrInstruments": "ask"
                ],
                "sandbox": [
                    "root": sandboxRoot.path,
                    "cache": sandboxCache.path
                ]
            ]
            return try JSONSerialization.data(withJSONObject: profile, options: [.sortedKeys])
        })
    }

    private func prepareSafeFixture(_ profile: TemporaryProfile) throws {
        try profile.write(
            Data("// Synthetic project marker".utf8),
            at: "repository/Safe.xcodeproj/project.pbxproj"
        )
        try profile.write(
            Data("struct SafeFixture {}".utf8),
            at: "repository/Sources/Safe.swift"
        )
        try profile.write(Data("safe cache".utf8), at: "sandbox/cache/.keep")
    }

    private func prepareEscapedSourceFixture(_ profile: TemporaryProfile) throws {
        try profile.write(
            Data("struct ExternalFixture {}".utf8),
            at: "outside/Sources/External.swift"
        )
        try profile.createSymbolicLink(
            at: "repository/EscapedSources",
            destination: "../outside/Sources"
        )
    }

    private func repositoryURL(for profile: TemporaryProfile) -> URL {
        profile.directory.appendingPathComponent("repository", isDirectory: true)
    }

    private func expectSuccessfulRemoval(of profile: TemporaryProfile) {
        #expect(throws: Never.self) {
            try profile.remove()
        }
    }
}

private let repositoryRootURL = URL(fileURLWithPath: #filePath, isDirectory: false)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .standardizedFileURL

private let invalidTraversalProfileURL = repositoryRootURL
    .appendingPathComponent("fixtures/profiles/invalid-path-traversal.json", isDirectory: false)

private let staticPolicyURL = repositoryRootURL
    .appendingPathComponent("policies/static-policy.json", isDirectory: false)
