import Foundation
import Testing
@testable import QualityCore

@Suite("Verifier result contracts")
struct VerifierContractTests {
    @Test("An empty check collection is blocked")
    func emptyEvidenceIsBlocked() {
        let report = QualityReport(command: "test", checks: [])

        #expect(report.status.rawValue == QualityStatus.blocked.rawValue)
        #expect(report.checks.count == 1)
        #expect(report.checks.first?.id == "QC.REPORT.NO_CHECKS")
        #expect(report.checks.first?.status.rawValue == QualityStatus.blocked.rawValue)
    }

    @Test("FAIL and BLOCKED take precedence over PASS")
    func aggregateStatusPrecedence() {
        let passingCheck = QualityCheck(id: "PASS", status: .pass, message: "pass")
        let blockedCheck = QualityCheck(id: "BLOCKED", status: .blocked, message: "blocked")
        let failingCheck = QualityCheck(id: "FAIL", status: .fail, message: "fail")

        let passingReport = QualityReport(command: "test", checks: [passingCheck])
        let blockedReport = QualityReport(
            command: "test",
            checks: [passingCheck, blockedCheck]
        )
        let failingReport = QualityReport(
            command: "test",
            checks: [passingCheck, blockedCheck, failingCheck]
        )

        #expect(passingReport.status.rawValue == QualityStatus.pass.rawValue)
        #expect(blockedReport.status.rawValue == QualityStatus.blocked.rawValue)
        #expect(failingReport.status.rawValue == QualityStatus.fail.rawValue)
    }

    @Test(
        "Malformed, unknown, duplicate, and oversized profiles never pass",
        arguments: InvalidProfileInput.allCases
    )
    func rejectedProfileNeverPasses(_ input: InvalidProfileInput) throws {
        let temporaryProfile = try TemporaryProfile(data: input.data)
        defer { temporaryProfile.remove() }

        let report = QualityCommands.validateProfile(at: temporaryProfile.url)

        #expect(report.status.rawValue == QualityStatus.fail.rawValue)
        #expect(report.checks.map(\.id) == ["QC.PROFILE.UNREADABLE"])
        #expect(
            report.checks.allSatisfy {
                $0.status.rawValue != QualityStatus.pass.rawValue
            }
        )
    }

    @Test("A valid closed profile remains the positive control")
    func validProfilePasses() throws {
        let temporaryProfile = try TemporaryProfile(data: Data(validProfileJSON.utf8))
        defer { temporaryProfile.remove() }

        let report = QualityCommands.validateProfile(at: temporaryProfile.url)

        #expect(report.status.rawValue == QualityStatus.pass.rawValue)
        #expect(report.checks.map(\.id) == ["QC.PROFILE.CONTRACT"])
    }
}

enum InvalidProfileInput: String, CaseIterable, Sendable {
    case malformed
    case unknownProperty
    case duplicateProperty
    case oversized

    var data: Data {
        switch self {
        case .malformed:
            return Data(#"{"schemaVersion":1"#.utf8)
        case .unknownProperty:
            return Data(profileWithUnknownPropertyJSON.utf8)
        case .duplicateProperty:
            return Data(profileWithDuplicatePropertyJSON.utf8)
        case .oversized:
            var data = Data(validProfileJSON.utf8)
            data.append(Data(repeating: 0x20, count: 1_000_001 - data.count))
            return data
        }
    }
}

private struct TemporaryProfile {
    let directory: URL
    let url: URL

    init(data: Data) throws {
        let repositoryRoot = URL(fileURLWithPath: #filePath, isDirectory: false)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .standardizedFileURL
        let cacheDirectory = repositoryRoot
        .appendingPathComponent(".quality-control-cache", isDirectory: true)
        let cacheRoot = cacheDirectory
        .appendingPathComponent("test-fixtures", isDirectory: true)

        try Self.ensurePlainDirectory(at: cacheDirectory)
        try Self.ensurePlainDirectory(at: cacheRoot)

        let resolvedRepositoryRoot = repositoryRoot.resolvingSymlinksInPath().standardizedFileURL
        let resolvedCacheRoot = cacheRoot.resolvingSymlinksInPath().standardizedFileURL
        guard Self.isStrictDescendant(resolvedCacheRoot, of: resolvedRepositoryRoot) else {
            throw FixtureBoundaryError()
        }

        directory = cacheRoot.appendingPathComponent(UUID().uuidString, isDirectory: true)
        url = directory.appendingPathComponent("profile.json", isDirectory: false)

        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false
        )

        let resolvedDirectory = directory.resolvingSymlinksInPath().standardizedFileURL
        guard Self.isStrictDescendant(resolvedDirectory, of: resolvedRepositoryRoot) else {
            throw FixtureBoundaryError()
        }

        try data.write(to: url, options: .atomic)
    }

    func remove() {
        try? FileManager.default.removeItem(at: directory)
    }

    private static func ensurePlainDirectory(at url: URL) throws {
        if FileManager.default.fileExists(atPath: url.path) {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            guard attributes[.type] as? FileAttributeType == .typeDirectory else {
                throw FixtureBoundaryError()
            }
            return
        }

        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: false
        )
    }

    private static func isStrictDescendant(_ candidate: URL, of root: URL) -> Bool {
        let rootComponents = root.pathComponents
        let candidateComponents = candidate.pathComponents
        return candidateComponents.count > rootComponents.count
            && candidateComponents.prefix(rootComponents.count).elementsEqual(rootComponents)
    }
}

private struct FixtureBoundaryError: Error {}

private let validProfileJSON = #"""
{
  "schemaVersion": 1,
  "project": {"kind": "xcodeproj", "path": "QualityControl.xcodeproj"},
  "scheme": "QualityControl",
  "sourcePaths": ["Sources"],
  "mode": "controlled",
  "permissions": {
    "testCreation": "ask",
    "testModification": "ask",
    "localTestExecution": "ask",
    "githubExecution": "manual",
    "uiTests": "ask",
    "simulatorOrDevice": "ask",
    "performanceOrInstruments": "ask"
  },
  "sandbox": {"root": "/quality-control-sandbox", "cache": "/quality-control-sandbox/cache"}
}
"""#

private let profileWithUnknownPropertyJSON = #"""
{
  "schemaVersion": 1,
  "project": {"kind": "xcodeproj", "path": "QualityControl.xcodeproj"},
  "scheme": "QualityControl",
  "sourcePaths": ["Sources"],
  "mode": "controlled",
  "permissions": {
    "testCreation": "ask",
    "testModification": "ask",
    "localTestExecution": "ask",
    "githubExecution": "manual",
    "uiTests": "ask",
    "simulatorOrDevice": "ask",
    "performanceOrInstruments": "ask"
  },
  "sandbox": {"root": "/quality-control-sandbox", "cache": "/quality-control-sandbox/cache"},
  "unexpected": true
}
"""#

private let profileWithDuplicatePropertyJSON = #"""
{
  "schemaVersion": 1,
  "schemaVersion": 1,
  "project": {"kind": "xcodeproj", "path": "QualityControl.xcodeproj"},
  "scheme": "QualityControl",
  "sourcePaths": ["Sources"],
  "mode": "controlled",
  "permissions": {
    "testCreation": "ask",
    "testModification": "ask",
    "localTestExecution": "ask",
    "githubExecution": "manual",
    "uiTests": "ask",
    "simulatorOrDevice": "ask",
    "performanceOrInstruments": "ask"
  },
  "sandbox": {"root": "/quality-control-sandbox", "cache": "/quality-control-sandbox/cache"}
}
"""#
