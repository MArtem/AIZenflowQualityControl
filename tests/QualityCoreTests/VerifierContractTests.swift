import Foundation
import Testing
import Darwin
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
        let blockedBeforePassingReport = QualityReport(
            command: "test",
            checks: [blockedCheck, passingCheck]
        )
        let failingBeforeLowerPriorityReport = QualityReport(
            command: "test",
            checks: [failingCheck, blockedCheck, passingCheck]
        )

        #expect(passingReport.status.rawValue == QualityStatus.pass.rawValue)
        #expect(blockedReport.status.rawValue == QualityStatus.blocked.rawValue)
        #expect(failingReport.status.rawValue == QualityStatus.fail.rawValue)
        #expect(blockedBeforePassingReport.status.rawValue == QualityStatus.blocked.rawValue)
        #expect(failingBeforeLowerPriorityReport.status.rawValue == QualityStatus.fail.rawValue)
    }

    @Test(
        "Malformed, unknown, duplicate, and oversized profiles never pass",
        arguments: InvalidProfileInput.allCases
    )
    func rejectedProfileNeverPasses(_ input: InvalidProfileInput) throws {
        let temporaryProfile = try TemporaryProfile(data: input.data)
        defer {
            #expect(throws: Never.self) {
                try temporaryProfile.remove()
            }
        }

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
        defer {
            #expect(throws: Never.self) {
                try temporaryProfile.remove()
            }
        }

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

        let createdDirectory = try Self.createUniqueDirectory(in: cacheRoot)
        let createdURL = createdDirectory.appendingPathComponent("profile.json", isDirectory: false)

        do {
            try Self.writePinned(
                data,
                fileName: createdURL.lastPathComponent,
                in: createdDirectory,
                repositoryRoot: resolvedRepositoryRoot
            )
        } catch {
            do {
                try FileManager.default.removeItem(at: createdDirectory)
            } catch let cleanupError {
                throw FixtureCleanupError(primary: error, cleanup: cleanupError)
            }
            throw error
        }

        directory = createdDirectory
        url = createdURL
    }

    func remove() throws {
        try FileManager.default.removeItem(at: directory)
    }

    private static func ensurePlainDirectory(at url: URL) throws {
        if mkdir(url.path, S_IRWXU) != 0 {
            let errorNumber = errno
            guard errorNumber == EEXIST else {
                throw FixtureFileSystemError(operation: "mkdir", code: errorNumber)
            }
        }

        _ = try plainDirectoryStatus(at: url)
    }

    private static func createUniqueDirectory(in parent: URL) throws -> URL {
        for _ in 0..<10 {
            let candidate = parent.appendingPathComponent(UUID().uuidString, isDirectory: true)
            if mkdir(candidate.path, S_IRWXU) == 0 {
                return candidate
            }

            let errorNumber = errno
            guard errorNumber == EEXIST else {
                throw FixtureFileSystemError(operation: "mkdir", code: errorNumber)
            }
        }

        throw FixtureBoundaryError()
    }

    private static func writePinned(
        _ data: Data,
        fileName: String,
        in directory: URL,
        repositoryRoot: URL
    ) throws {
        let directoryDescriptor = open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard directoryDescriptor >= 0 else {
            throw FixtureFileSystemError(operation: "open", code: errno)
        }
        defer { close(directoryDescriptor) }

        var openedStatus = stat()
        guard fstat(directoryDescriptor, &openedStatus) == 0 else {
            throw FixtureFileSystemError(operation: "fstat", code: errno)
        }

        let fileDescriptor = openat(
            directoryDescriptor,
            fileName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            S_IRUSR | S_IWUSR
        )
        guard fileDescriptor >= 0 else {
            throw FixtureFileSystemError(operation: "openat", code: errno)
        }

        let handle = FileHandle(fileDescriptor: fileDescriptor, closeOnDealloc: true)
        try handle.write(contentsOf: data)
        try handle.close()

        let currentStatus = try plainDirectoryStatus(at: directory)
        guard currentStatus.st_dev == openedStatus.st_dev,
              currentStatus.st_ino == openedStatus.st_ino else {
            throw FixtureBoundaryError()
        }

        let resolvedDirectory = directory.resolvingSymlinksInPath().standardizedFileURL
        guard isStrictDescendant(resolvedDirectory, of: repositoryRoot) else {
            throw FixtureBoundaryError()
        }
    }

    private static func plainDirectoryStatus(at url: URL) throws -> stat {
        var status = stat()
        guard lstat(url.path, &status) == 0 else {
            throw FixtureFileSystemError(operation: "lstat", code: errno)
        }
        guard status.st_mode & S_IFMT == S_IFDIR else {
            throw FixtureBoundaryError()
        }
        return status
    }

    private static func isStrictDescendant(_ candidate: URL, of root: URL) -> Bool {
        let rootComponents = root.pathComponents
        let candidateComponents = candidate.pathComponents
        return candidateComponents.count > rootComponents.count
            && candidateComponents.prefix(rootComponents.count).elementsEqual(rootComponents)
    }
}

private struct FixtureBoundaryError: Error {}

private struct FixtureFileSystemError: Error {
    let operation: String
    let code: Int32
}

private struct FixtureCleanupError: Error {
    let primary: Error
    let cleanup: Error
}

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
