import Foundation
import Testing
@testable import QualityCore

@Suite("Static policy and bounded scan contracts")
struct StaticPolicyContractTests {
    @Test(
        "Malformed, unknown, duplicate, and oversized policies never pass",
        arguments: RejectedStaticPolicyInput.allCases
    )
    func rejectedPolicyNeverPasses(_ input: RejectedStaticPolicyInput) throws {
        let policy = try TemporaryProfile(data: input.data)
        defer { expectSuccessfulRemoval(of: policy) }

        let report = QualityCommands.staticScan(
            profileURL: validProfileURL,
            policyURL: policy.url,
            repositoryRoot: packageRootURL
        )

        #expect(report.status.rawValue == QualityStatus.fail.rawValue)
        #expect(report.checks.map(\.id) == ["QC.POLICY.UNREADABLE"])
        #expect(report.checks.allSatisfy { $0.status.rawValue != QualityStatus.pass.rawValue })
    }

    @Test(
        "Invalid policy contracts fail before repository scanning",
        arguments: InvalidStaticPolicyContract.allCases
    )
    func invalidPolicyContractFails(_ input: InvalidStaticPolicyContract) throws {
        let policy = try TemporaryProfile(data: try input.data())
        defer { expectSuccessfulRemoval(of: policy) }

        let report = QualityCommands.staticScan(
            profileURL: validProfileURL,
            policyURL: policy.url,
            repositoryRoot: packageRootURL
        )

        #expect(report.status.rawValue == QualityStatus.fail.rawValue)
        #expect(report.checks.map(\.id) == [input.expectedCheckID])
        #expect(!report.checks.contains { $0.id == "QC.STATIC.SCAN" })
    }

    @Test("A source scope with no regular files is blocked")
    func emptySourceScopeIsBlocked() throws {
        let profile = try makeScanProfile()
        defer { expectSuccessfulRemoval(of: profile) }
        try profile.createDirectory(at: "repository/Sources")

        let report = QualityCommands.staticScan(
            profileURL: profile.url,
            policyURL: defaultStaticPolicyURL,
            repositoryRoot: repositoryURL(for: profile)
        )

        #expect(report.status.rawValue == QualityStatus.blocked.rawValue)
        #expect(
            report.checks.contains {
                $0.id == "QC.STATIC.NO_FILES_SCANNED"
                    && $0.status.rawValue == QualityStatus.blocked.rawValue
            }
        )
        #expect(!report.checks.contains { $0.id == "QC.STATIC.SCAN" })
    }

    @Test("A file over the configured byte limit fails the scan")
    func oversizedSourceFileFails() throws {
        let profile = try makeScanProfile()
        defer { expectSuccessfulRemoval(of: profile) }
        let policy = try TemporaryProfile(data: try policyData(maximumFileBytes: 3))
        defer { expectSuccessfulRemoval(of: policy) }
        try profile.write(Data("four".utf8), at: "repository/Sources/Oversized.swift")

        let report = QualityCommands.staticScan(
            profileURL: profile.url,
            policyURL: policy.url,
            repositoryRoot: repositoryURL(for: profile)
        )

        #expect(report.status.rawValue == QualityStatus.fail.rawValue)
        #expect(
            report.checks.contains {
                $0.id == "QC.STATIC.OVERSIZED_FILE"
                    && $0.status.rawValue == QualityStatus.fail.rawValue
                    && $0.path == "Sources/Oversized.swift"
            }
        )
        #expect(!report.checks.contains { $0.id == "QC.STATIC.SCAN" })
    }

    @Test("A forbidden artifact suffix fails the scan")
    func forbiddenArtifactFails() throws {
        let profile = try makeScanProfile()
        defer { expectSuccessfulRemoval(of: profile) }
        try profile.write(Data("artifact".utf8), at: "repository/Sources/Result.xcresult")

        let report = QualityCommands.staticScan(
            profileURL: profile.url,
            policyURL: defaultStaticPolicyURL,
            repositoryRoot: repositoryURL(for: profile)
        )

        #expect(report.status.rawValue == QualityStatus.fail.rawValue)
        #expect(
            report.checks.contains {
                $0.id == "QC.STATIC.FORBIDDEN_ARTIFACT"
                    && $0.status.rawValue == QualityStatus.fail.rawValue
                    && $0.path == "Sources/Result.xcresult"
            }
        )
        #expect(!report.checks.contains { $0.id == "QC.STATIC.SCAN" })
    }

    @Test("Overlapping source scopes fail before scanning")
    func overlappingSourceScopesFail() throws {
        let profile = try makeScanProfile(sourcePaths: ["Sources", "ZAlias"])
        defer { expectSuccessfulRemoval(of: profile) }
        try profile.write(Data("struct Nested {}".utf8), at: "repository/Sources/Nested/File.swift")
        try profile.createSymbolicLink(
            at: "repository/ZAlias",
            destination: "Sources/Nested"
        )

        let report = QualityCommands.staticScan(
            profileURL: profile.url,
            policyURL: defaultStaticPolicyURL,
            repositoryRoot: repositoryURL(for: profile)
        )

        #expect(report.status.rawValue == QualityStatus.fail.rawValue)
        #expect(
            report.checks.contains {
                $0.id == "QC.STATIC.OVERLAPPING_SOURCE_SCOPE"
                    && $0.status.rawValue == QualityStatus.fail.rawValue
                    && $0.path == "ZAlias"
            }
        )
        #expect(!report.checks.contains { $0.id == "QC.STATIC.SCAN" })
    }

    private func makeScanProfile(
        sourcePaths: [String] = ["Sources"]
    ) throws -> TemporaryProfile {
        try TemporaryProfile(dataProvider: { directory in
            let sandboxRoot = directory.appendingPathComponent("sandbox", isDirectory: true)
            let profile: [String: Any] = [
                "schemaVersion": 1,
                "project": ["kind": "xcodeproj", "path": "Safe.xcodeproj"],
                "scheme": "StaticPolicyFixture",
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
                    "cache": sandboxRoot.appendingPathComponent("cache", isDirectory: true).path
                ]
            ]
            return try JSONSerialization.data(withJSONObject: profile, options: [.sortedKeys])
        })
    }

    private func repositoryURL(for profile: TemporaryProfile) -> URL {
        profile.directory.appendingPathComponent("repository", isDirectory: true)
    }

    private func expectSuccessfulRemoval(of fixture: TemporaryProfile) {
        #expect(throws: Never.self) {
            try fixture.remove()
        }
    }
}

enum RejectedStaticPolicyInput: String, CaseIterable, Sendable {
    case malformed
    case unknownProperty
    case duplicateProperty
    case oversized

    var data: Data {
        switch self {
        case .malformed:
            Data(#"{"schemaVersion":1,"#.utf8)
        case .unknownProperty:
            Data(
                #"""
                {
                  "schemaVersion": 1,
                  "maximumFileBytes": 10,
                  "excludedDirectoryNames": [],
                  "forbiddenFileSuffixes": [],
                  "unexpected": true
                }
                """#.utf8
            )
        case .duplicateProperty:
            Data(
                #"""
                {
                  "schemaVersion": 1,
                  "schemaVersion": 1,
                  "maximumFileBytes": 10,
                  "excludedDirectoryNames": [],
                  "forbiddenFileSuffixes": []
                }
                """#.utf8
            )
        case .oversized:
            Data(repeating: 0x20, count: 1_000_001)
        }
    }
}

enum InvalidStaticPolicyContract: String, CaseIterable, Sendable {
    case unsupportedSchema
    case invalidFileLimit
    case listLimit
    case invalidExcludedDirectory
    case invalidFileSuffix
    case duplicateExcludedDirectory
    case duplicateFileSuffix

    var expectedCheckID: String {
        switch self {
        case .unsupportedSchema:
            "QC.POLICY.UNSUPPORTED_SCHEMA"
        case .invalidFileLimit:
            "QC.POLICY.INVALID_FILE_LIMIT"
        case .listLimit:
            "QC.POLICY.LIST_LIMIT"
        case .invalidExcludedDirectory:
            "QC.POLICY.INVALID_EXCLUDED_DIRECTORY"
        case .invalidFileSuffix:
            "QC.POLICY.INVALID_FILE_SUFFIX"
        case .duplicateExcludedDirectory:
            "QC.POLICY.DUPLICATE_EXCLUDED_DIRECTORY"
        case .duplicateFileSuffix:
            "QC.POLICY.DUPLICATE_FILE_SUFFIX"
        }
    }

    func data() throws -> Data {
        var schemaVersion = 1
        var maximumFileBytes = 10
        var excludedDirectoryNames: [String] = []
        var forbiddenFileSuffixes: [String] = []

        switch self {
        case .unsupportedSchema:
            schemaVersion = 2
        case .invalidFileLimit:
            maximumFileBytes = 0
        case .listLimit:
            excludedDirectoryNames = (0...256).map { "Excluded\($0)" }
        case .invalidExcludedDirectory:
            excludedDirectoryNames = ["Nested/Build"]
        case .invalidFileSuffix:
            forbiddenFileSuffixes = ["xcresult"]
        case .duplicateExcludedDirectory:
            excludedDirectoryNames = ["Build", "Build"]
        case .duplicateFileSuffix:
            forbiddenFileSuffixes = [".xcresult", ".XCRESULT"]
        }

        return try policyData(
            schemaVersion: schemaVersion,
            maximumFileBytes: maximumFileBytes,
            excludedDirectoryNames: excludedDirectoryNames,
            forbiddenFileSuffixes: forbiddenFileSuffixes
        )
    }
}

private func policyData(
    schemaVersion: Int = 1,
    maximumFileBytes: Int = 5_000_000,
    excludedDirectoryNames: [String] = [".git", ".build", "DerivedData"],
    forbiddenFileSuffixes: [String] = [".xcresult", ".xcarchive", ".ipa"]
) throws -> Data {
    let policy: [String: Any] = [
        "schemaVersion": schemaVersion,
        "maximumFileBytes": maximumFileBytes,
        "excludedDirectoryNames": excludedDirectoryNames,
        "forbiddenFileSuffixes": forbiddenFileSuffixes
    ]
    return try JSONSerialization.data(withJSONObject: policy, options: [.sortedKeys])
}

private let packageRootURL = URL(fileURLWithPath: #filePath, isDirectory: false)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .standardizedFileURL

private let validProfileURL = packageRootURL
    .appendingPathComponent("fixtures/profiles/valid-minimal.json", isDirectory: false)

private let defaultStaticPolicyURL = packageRootURL
    .appendingPathComponent("policies/static-policy.json", isDirectory: false)
