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

    @Test(
        "Policy weakening fails before repository scanning",
        arguments: WeakeningStaticPolicyContract.allCases
    )
    func policyWeakeningFails(_ input: WeakeningStaticPolicyContract) throws {
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

    @Test(
        "Committed static fixtures preserve deliberate PASS and FAIL results",
        arguments: StaticFixtureContract.allCases
    )
    func committedStaticFixturesPreserveResults(_ input: StaticFixtureContract) throws {
        let profile = try makeScanProfile()
        defer { expectSuccessfulRemoval(of: profile) }

        let report = QualityCommands.staticScan(
            profileURL: profile.url,
            policyURL: input.policyURL,
            repositoryRoot: input.repositoryURL
        )

        #expect(report.status.rawValue == input.expectedStatus)
        #expect(
            report.checks
                .filter { $0.id == "QC.STATIC.FORBIDDEN_ARTIFACT" }
                .compactMap(\.path) == input.expectedForbiddenArtifactPaths
        )
        #expect(
            report.checks.contains {
                $0.id == "QC.STATIC.SCAN"
                    && $0.status.rawValue == QualityStatus.pass.rawValue
            } == input.expectsNormalScanPass
        )
    }

    @Test("Schema version 2 static scans remain blocked by default")
    func schemaV2StaticScanRequiresGraphByDefault() throws {
        let profile = try makeSchemaV2ScanProfile()
        defer { expectSuccessfulRemoval(of: profile) }
        try profile.write(Data("struct SafeFixture {}".utf8), at: "repository/Sources/Safe.swift")

        let report = QualityCommands.staticScan(
            profileURL: profile.url,
            policyURL: defaultStaticPolicyURL,
            repositoryRoot: repositoryURL(for: profile)
        )

        #expect(report.status.rawValue == QualityStatus.blocked.rawValue)
        #expect(report.checks.contains {
            $0.id == "QC.PROFILE.XCODE_GRAPH_RESOLUTION_REQUIRED"
                && $0.status == .blocked
        })
    }

    @Test("Explicit source-path scope discloses missing Xcode membership and scans safely")
    func schemaV2ExplicitSourcePathScopePasses() throws {
        let profile = try makeSchemaV2ScanProfile()
        defer { expectSuccessfulRemoval(of: profile) }
        try profile.write(Data("struct SafeFixture {}".utf8), at: "repository/Sources/Safe.swift")

        let report = QualityCommands.staticScan(
            profileURL: profile.url,
            policyURL: defaultStaticPolicyURL,
            repositoryRoot: repositoryURL(for: profile),
            scope: .explicitSourcePaths
        )

        #expect(report.status.rawValue == QualityStatus.pass.rawValue)
        #expect(report.checks.contains {
            $0.id == "QC.STATIC.SCOPE"
                && $0.status == .pass
                && $0.message.contains("Xcode target membership is not asserted")
        })
        #expect(report.checks.contains { $0.id == "QC.STATIC.SCAN" && $0.status == .pass })
        #expect(!report.checks.contains { $0.id == "QC.PROFILE.XCODE_GRAPH_RESOLUTION_REQUIRED" })
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

    @Test("The entry ceiling blocks a scan without creating a high-volume fixture")
    func entryCeilingBlocksScan() throws {
        let profile = try makeScanProfile()
        defer { expectSuccessfulRemoval(of: profile) }
        try profile.write(Data("a".utf8), at: "repository/Sources/A.swift")
        try profile.write(Data("b".utf8), at: "repository/Sources/B.swift")
        try profile.write(Data("c".utf8), at: "repository/Sources/C.swift")

        let report = QualityCommands.staticScan(
            profileURL: profile.url,
            policyURL: defaultStaticPolicyURL,
            repositoryRoot: repositoryURL(for: profile),
            limits: StaticScanLimits(maximumEntries: 2, maximumFindings: 10)
        )

        #expect(report.status.rawValue == QualityStatus.blocked.rawValue)
        let limitCheck = try #require(
            report.checks.first { $0.id == "QC.STATIC.SCAN_LIMIT_REACHED" }
        )
        #expect(limitCheck.status.rawValue == QualityStatus.blocked.rawValue)
        #expect(
            limitCheck.message
                == "Static scan stopped after reaching the entry limit of 2."
        )
        #expect(!report.checks.contains { $0.id == "QC.STATIC.SCAN" })
    }

    @Test("The finding ceiling fails closed without creating a high-volume fixture")
    func findingCeilingFailsClosed() throws {
        let profile = try makeScanProfile()
        defer { expectSuccessfulRemoval(of: profile) }
        try profile.write(Data("a".utf8), at: "repository/Sources/A.xcresult")
        try profile.write(Data("b".utf8), at: "repository/Sources/B.xcresult")
        try profile.write(Data("c".utf8), at: "repository/Sources/C.xcresult")

        let report = QualityCommands.staticScan(
            profileURL: profile.url,
            policyURL: defaultStaticPolicyURL,
            repositoryRoot: repositoryURL(for: profile),
            limits: StaticScanLimits(maximumEntries: 10, maximumFindings: 2)
        )

        #expect(report.status.rawValue == QualityStatus.fail.rawValue)
        let findings = report.checks.filter { $0.id == "QC.STATIC.FORBIDDEN_ARTIFACT" }
        #expect(findings.map(\.path) == [
            "Sources/A.xcresult",
            "Sources/B.xcresult"
        ])
        let limitCheck = try #require(
            report.checks.first { $0.id == "QC.STATIC.SCAN_LIMIT_REACHED" }
        )
        #expect(limitCheck.status.rawValue == QualityStatus.blocked.rawValue)
        #expect(
            limitCheck.message
                == "Static scan stopped after reaching the finding limit of 2."
        )
        #expect(!report.checks.contains { $0.id == "QC.STATIC.SCAN" })
    }

    @Test("A cooperative deadline blocks a partial scan without waiting")
    func cooperativeDeadlineBlocksPartialScan() throws {
        let profile = try makeScanProfile()
        defer { expectSuccessfulRemoval(of: profile) }
        try profile.write(Data("a".utf8), at: "repository/Sources/A.swift")
        try profile.write(Data("b".utf8), at: "repository/Sources/B.swift")
        try profile.write(Data("c".utf8), at: "repository/Sources/C.swift")

        let report = QualityCommands.staticScan(
            profileURL: profile.url,
            policyURL: defaultStaticPolicyURL,
            repositoryRoot: repositoryURL(for: profile),
            limits: StaticScanLimits(maximumEntries: 10, maximumFindings: 10),
            deadlineExceeded: { scannedEntries, _ in scannedEntries >= 2 }
        )

        #expect(report.status.rawValue == QualityStatus.blocked.rawValue)
        let timeoutChecks = report.checks.filter { $0.id == "QC.STATIC.TIMEOUT" }
        let timeoutCheck = try #require(timeoutChecks.first)
        #expect(timeoutChecks.count == 1)
        #expect(timeoutCheck.status.rawValue == QualityStatus.blocked.rawValue)
        #expect(
            timeoutCheck.message
                == "Static scan exceeded its cooperative execution deadline."
        )
        #expect(!report.checks.contains { $0.id == "QC.STATIC.SCAN" })
    }

    @Test("A finding before the cooperative deadline remains a failure")
    func findingBeforeCooperativeDeadlineRemainsFailure() throws {
        let profile = try makeScanProfile()
        defer { expectSuccessfulRemoval(of: profile) }
        try profile.write(Data("a".utf8), at: "repository/Sources/A.xcresult")
        try profile.write(Data("b".utf8), at: "repository/Sources/B.xcresult")
        try profile.write(Data("c".utf8), at: "repository/Sources/C.xcresult")

        let report = QualityCommands.staticScan(
            profileURL: profile.url,
            policyURL: defaultStaticPolicyURL,
            repositoryRoot: repositoryURL(for: profile),
            limits: StaticScanLimits(maximumEntries: 10, maximumFindings: 10),
            deadlineExceeded: { _, reportedFindings in reportedFindings >= 1 }
        )

        #expect(report.status.rawValue == QualityStatus.fail.rawValue)
        let findings = report.checks.filter { $0.id == "QC.STATIC.FORBIDDEN_ARTIFACT" }
        #expect(findings.map(\.path) == ["Sources/A.xcresult"])
        let timeoutChecks = report.checks.filter { $0.id == "QC.STATIC.TIMEOUT" }
        let timeoutCheck = try #require(timeoutChecks.first)
        #expect(timeoutChecks.count == 1)
        #expect(timeoutCheck.status.rawValue == QualityStatus.blocked.rawValue)
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

    private func makeSchemaV2ScanProfile() throws -> TemporaryProfile {
        try TemporaryProfile(dataProvider: { _ in
            let profile: [String: Any] = [
                "schemaVersion": 2,
                "project": ["kind": "xcodeproj", "path": "Safe.xcodeproj"],
                "sourcePaths": ["Sources"],
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
                "sandbox": ["root": ".quality-control", "cache": ".quality-control/cache"],
                "engine": [
                    "version": "0.1.0-dev",
                    "revision": String(repeating: "a", count: 40)
                ],
                "xcode": [
                    "sourceMembership": ["authority": "xcode-build-graph"],
                    "schemes": [[
                        "name": "Safe",
                        "targets": ["Safe"],
                        "configurations": ["Debug"],
                        "destinations": ["platform=macOS"],
                        "testPlans": []
                    ]]
                ],
                "applicability": CapabilityID.allCases.map { capability in
                    [
                        "capability": capability.rawValue,
                        "status": "notApplicable",
                        "reason": "Synthetic static-scope fixture.",
                        "owner": "Test",
                        "revisitCondition": "Fixture changes."
                    ]
                }
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
        var maximumFileBytes = 5_000_000
        var excludedDirectoryNames = [".git", ".build", "DerivedData"]
        var forbiddenFileSuffixes = [".xcresult", ".xcarchive", ".ipa"]

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

enum WeakeningStaticPolicyContract: String, CaseIterable, Sendable {
    case excessiveFileLimit
    case unauthorizedExcludedDirectory
    case missingRequiredFileSuffix

    var expectedCheckID: String {
        switch self {
        case .excessiveFileLimit:
            "QC.POLICY.FILE_LIMIT_WEAKENING"
        case .unauthorizedExcludedDirectory:
            "QC.POLICY.EXCLUDED_DIRECTORY_WEAKENING"
        case .missingRequiredFileSuffix:
            "QC.POLICY.FORBIDDEN_SUFFIX_WEAKENING"
        }
    }

    func data() throws -> Data {
        switch self {
        case .excessiveFileLimit:
            try policyData(maximumFileBytes: 5_000_001)
        case .unauthorizedExcludedDirectory:
            try policyData(
                excludedDirectoryNames: [".git", ".build", "DerivedData", "Generated"]
            )
        case .missingRequiredFileSuffix:
            try policyData(forbiddenFileSuffixes: [".xcresult", ".xcarchive"])
        }
    }
}

enum StaticFixtureContract: String, CaseIterable, Sendable {
    case passing
    case deliberateFailureWithCanonicalPolicy
    case deliberateFailure

    var repositoryURL: URL {
        packageRootURL.appendingPathComponent(
            repositoryRelativePath,
            isDirectory: true
        )
    }

    var policyURL: URL {
        switch self {
        case .passing, .deliberateFailureWithCanonicalPolicy:
            defaultStaticPolicyURL
        case .deliberateFailure:
            packageRootURL.appendingPathComponent(
                "fixtures/policies/deliberate-failure-static-policy.json",
                isDirectory: false
            )
        }
    }

    var expectedStatus: String {
        switch self {
        case .passing, .deliberateFailureWithCanonicalPolicy:
            QualityStatus.pass.rawValue
        case .deliberateFailure:
            QualityStatus.fail.rawValue
        }
    }

    var expectedForbiddenArtifactPaths: [String] {
        switch self {
        case .passing, .deliberateFailureWithCanonicalPolicy:
            []
        case .deliberateFailure:
            ["Sources/DeliberateFailure.canary-fail"]
        }
    }

    var expectsNormalScanPass: Bool {
        self != .deliberateFailure
    }

    private var repositoryRelativePath: String {
        switch self {
        case .passing:
            "fixtures/static/passing-project"
        case .deliberateFailureWithCanonicalPolicy, .deliberateFailure:
            "fixtures/static/failing-project"
        }
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
