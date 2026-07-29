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

private final class TemporaryProfile {
    let url: URL
    private let directoryName: String
    private var fixtureRootDescriptor: Int32
    private var directoryDescriptor: Int32

    init(data: Data) throws {
        let repositoryRoot = URL(fileURLWithPath: #filePath, isDirectory: false)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .standardizedFileURL
        let resolvedRepositoryRoot = repositoryRoot.resolvingSymlinksInPath().standardizedFileURL
        let cacheDirectory = repositoryRoot
            .appendingPathComponent(".quality-control-cache", isDirectory: true)
        let cacheRoot = cacheDirectory
            .appendingPathComponent("test-fixtures", isDirectory: true)

        let repositoryDescriptor = try Self.openPinnedDirectory(at: repositoryRoot)
        defer { Darwin.close(repositoryDescriptor) }
        try Self.validatePinnedDirectory(
            repositoryDescriptor,
            at: repositoryRoot,
            repositoryRoot: resolvedRepositoryRoot,
            allowsRepositoryRoot: true
        )

        let cacheDescriptor = try Self.openOrCreatePlainDirectory(
            named: cacheDirectory.lastPathComponent,
            at: cacheDirectory,
            parentDescriptor: repositoryDescriptor,
            repositoryRoot: resolvedRepositoryRoot
        )
        defer { Darwin.close(cacheDescriptor) }

        let openedFixtureRootDescriptor = try Self.openOrCreatePlainDirectory(
            named: cacheRoot.lastPathComponent,
            at: cacheRoot,
            parentDescriptor: cacheDescriptor,
            repositoryRoot: resolvedRepositoryRoot
        )
        var ownsFixtureRootDescriptor = true
        defer {
            if ownsFixtureRootDescriptor {
                Darwin.close(openedFixtureRootDescriptor)
            }
        }

        let created = try Self.createUniqueDirectory(
            in: cacheRoot,
            parentDescriptor: openedFixtureRootDescriptor,
            repositoryRoot: resolvedRepositoryRoot
        )
        var ownsDirectoryDescriptor = true
        defer {
            if ownsDirectoryDescriptor {
                Darwin.close(created.descriptor)
            }
        }
        let createdURL = created.url.appendingPathComponent("profile.json", isDirectory: false)

        do {
            try Self.writePinned(
                data,
                fileName: createdURL.lastPathComponent,
                directoryDescriptor: created.descriptor
            )
            try Self.validatePinnedDirectory(
                created.descriptor,
                at: created.url,
                repositoryRoot: resolvedRepositoryRoot
            )
        } catch {
            let cleanupError = Self.removeCreatedFixture(
                fileName: createdURL.lastPathComponent,
                directoryName: created.name,
                directoryDescriptor: created.descriptor,
                parentDescriptor: openedFixtureRootDescriptor,
                missingFileIsAllowed: true
            )
            ownsDirectoryDescriptor = false
            if let cleanupError {
                throw FixtureCleanupError(primary: error, cleanup: cleanupError)
            }
            throw error
        }

        url = createdURL
        directoryName = created.name
        fixtureRootDescriptor = openedFixtureRootDescriptor
        directoryDescriptor = created.descriptor
        ownsFixtureRootDescriptor = false
        ownsDirectoryDescriptor = false
    }

    func remove() throws {
        guard directoryDescriptor >= 0, fixtureRootDescriptor >= 0 else {
            return
        }

        let cleanupError = Self.removeCreatedFixture(
            fileName: url.lastPathComponent,
            directoryName: directoryName,
            directoryDescriptor: directoryDescriptor,
            parentDescriptor: fixtureRootDescriptor,
            missingFileIsAllowed: false
        )
        directoryDescriptor = -1

        let closeResult = Darwin.close(fixtureRootDescriptor)
        let closeError = closeResult == 0
            ? nil
            : FixtureFileSystemError(operation: "close", code: errno)
        fixtureRootDescriptor = -1

        if let cleanupError {
            throw cleanupError
        }
        if let closeError {
            throw closeError
        }
    }

    deinit {
        if directoryDescriptor >= 0 {
            Darwin.close(directoryDescriptor)
        }
        if fixtureRootDescriptor >= 0 {
            Darwin.close(fixtureRootDescriptor)
        }
    }

    private static func openPinnedDirectory(at url: URL) throws -> Int32 {
        let descriptor = Darwin.open(
            url.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw FixtureFileSystemError(operation: "open", code: errno)
        }
        return descriptor
    }

    private static func openOrCreatePlainDirectory(
        named name: String,
        at url: URL,
        parentDescriptor: Int32,
        repositoryRoot: URL
    ) throws -> Int32 {
        if mkdirat(parentDescriptor, name, S_IRWXU) != 0 {
            let errorNumber = errno
            guard errorNumber == EEXIST else {
                throw FixtureFileSystemError(operation: "mkdirat", code: errorNumber)
            }
        }

        let descriptor = openat(
            parentDescriptor,
            name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw FixtureFileSystemError(operation: "openat", code: errno)
        }

        do {
            try validatePinnedDirectory(
                descriptor,
                at: url,
                repositoryRoot: repositoryRoot
            )
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    private static func createUniqueDirectory(
        in parent: URL,
        parentDescriptor: Int32,
        repositoryRoot: URL
    ) throws -> (name: String, url: URL, descriptor: Int32) {
        for _ in 0..<10 {
            let name = UUID().uuidString
            let candidate = parent.appendingPathComponent(name, isDirectory: true)
            if mkdirat(parentDescriptor, name, S_IRWXU) == 0 {
                let descriptor = openat(
                    parentDescriptor,
                    name,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
                )
                guard descriptor >= 0 else {
                    let primaryError = FixtureFileSystemError(operation: "openat", code: errno)
                    if unlinkat(parentDescriptor, name, AT_REMOVEDIR) != 0 {
                        let cleanupError = FixtureFileSystemError(
                            operation: "unlinkat",
                            code: errno
                        )
                        throw FixtureCleanupError(primary: primaryError, cleanup: cleanupError)
                    }
                    throw primaryError
                }

                do {
                    try validatePinnedDirectory(
                        descriptor,
                        at: candidate,
                        repositoryRoot: repositoryRoot
                    )
                    return (name, candidate, descriptor)
                } catch {
                    Darwin.close(descriptor)
                    if unlinkat(parentDescriptor, name, AT_REMOVEDIR) != 0 {
                        let cleanupError = FixtureFileSystemError(
                            operation: "unlinkat",
                            code: errno
                        )
                        throw FixtureCleanupError(primary: error, cleanup: cleanupError)
                    }
                    throw error
                }
            }

            let errorNumber = errno
            guard errorNumber == EEXIST else {
                throw FixtureFileSystemError(operation: "mkdirat", code: errorNumber)
            }
        }

        throw FixtureBoundaryError()
    }

    private static func writePinned(
        _ data: Data,
        fileName: String,
        directoryDescriptor: Int32
    ) throws {
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
    }

    private static func removeCreatedFixture(
        fileName: String,
        directoryName: String,
        directoryDescriptor: Int32,
        parentDescriptor: Int32,
        missingFileIsAllowed: Bool
    ) -> Error? {
        var firstError: Error?

        if unlinkat(directoryDescriptor, fileName, 0) != 0 {
            let errorNumber = errno
            if !(missingFileIsAllowed && errorNumber == ENOENT) {
                firstError = FixtureFileSystemError(operation: "unlinkat", code: errorNumber)
            }
        }

        if Darwin.close(directoryDescriptor) != 0, firstError == nil {
            firstError = FixtureFileSystemError(operation: "close", code: errno)
        }

        if unlinkat(parentDescriptor, directoryName, AT_REMOVEDIR) != 0, firstError == nil {
            firstError = FixtureFileSystemError(operation: "unlinkat", code: errno)
        }

        return firstError
    }

    private static func validatePinnedDirectory(
        _ descriptor: Int32,
        at url: URL,
        repositoryRoot: URL,
        allowsRepositoryRoot: Bool = false
    ) throws {
        var descriptorStatus = stat()
        guard fstat(descriptor, &descriptorStatus) == 0 else {
            throw FixtureFileSystemError(operation: "fstat", code: errno)
        }

        var pathStatus = stat()
        guard lstat(url.path, &pathStatus) == 0 else {
            throw FixtureFileSystemError(operation: "lstat", code: errno)
        }
        guard pathStatus.st_mode & S_IFMT == S_IFDIR,
              pathStatus.st_dev == descriptorStatus.st_dev,
              pathStatus.st_ino == descriptorStatus.st_ino else {
            throw FixtureBoundaryError()
        }

        let resolvedDirectory = url.resolvingSymlinksInPath().standardizedFileURL
        let isAllowed = allowsRepositoryRoot
            ? resolvedDirectory.pathComponents == repositoryRoot.pathComponents
            : isStrictDescendant(resolvedDirectory, of: repositoryRoot)
        guard isAllowed else {
            throw FixtureBoundaryError()
        }
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
