import Darwin
import Foundation
import Testing
@testable import QualityCore

@Suite("Evidence artifact hashing")
struct EvidenceArtifactHasherTests {
    @Test("An empty artifact set needs no filesystem access")
    func acceptsEmptyArtifactSet() throws {
        let artifacts = try EvidenceArtifactHasher.hashInWorker(
            relativePaths: [],
            repositoryRoot: URL(
                fileURLWithPath: ".quality-control-cache/missing-evidence-root",
                isDirectory: true
            )
        )

        #expect(artifacts.isEmpty)
    }

    @Test("Regular artifacts are hashed in deterministic path order")
    func hashesRegularArtifacts() throws {
        let fixture = try TemporaryProfile(data: Data("{}".utf8))
        defer { expectSuccessfulRemoval(of: fixture) }
        try fixture.write(Data("abc".utf8), at: "reports/z.json")
        try fixture.write(Data(), at: "reports/a.json")

        let artifacts = try EvidenceArtifactHasher.hashInWorker(
            relativePaths: ["reports/z.json", "reports/a.json"],
            repositoryRoot: fixture.directory
        )

        #expect(artifacts.map(\.path) == ["reports/a.json", "reports/z.json"])
        #expect(artifacts.map(\.sha256) == [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ])
    }

    @Test(
        "Unsafe artifact paths fail before filesystem access",
        arguments: [
            "",
            "/absolute",
            "../outside",
            "reports/../outside",
            "reports//file",
            "./file",
            "~report",
            "~/report",
            " ",
            "\u{200B}"
        ]
    )
    func rejectsUnsafePath(_ path: String) throws {
        let fixture = try TemporaryProfile(data: Data("{}".utf8))
        defer { expectSuccessfulRemoval(of: fixture) }

        expectError(.invalidPath) {
            try EvidenceArtifactHasher.hashInWorker(
                relativePaths: [path],
                repositoryRoot: fixture.directory
            )
        }
    }

    @Test("Overlong artifact paths fail with bounded work")
    func rejectsOverlongPath() throws {
        let fixture = try TemporaryProfile(data: Data("{}".utf8))
        defer { expectSuccessfulRemoval(of: fixture) }

        expectError(.invalidPath) {
            try EvidenceArtifactHasher.hashInWorker(
                relativePaths: [String(repeating: "a", count: 1_025)],
                repositoryRoot: fixture.directory
            )
        }
    }

    @Test("Duplicate and excessive artifact sets fail closed")
    func rejectsInvalidCollections() throws {
        let fixture = try TemporaryProfile(data: Data("{}".utf8))
        defer { expectSuccessfulRemoval(of: fixture) }

        expectError(.duplicatePath) {
            try EvidenceArtifactHasher.hashInWorker(
                relativePaths: ["report.json", "report.json"],
                repositoryRoot: fixture.directory
            )
        }
        expectError(.tooManyArtifacts) {
            try EvidenceArtifactHasher.hashInWorker(
                relativePaths: (0...EvidenceArtifactHasher.maximumArtifactCount).map {
                    "report-\($0).json"
                },
                repositoryRoot: fixture.directory
            )
        }
    }

    @Test("Symlinks and directories cannot become file evidence")
    func rejectsNonRegularArtifacts() throws {
        let fixture = try TemporaryProfile(data: Data("{}".utf8))
        defer { expectSuccessfulRemoval(of: fixture) }
        try fixture.write(Data("outside".utf8), at: "outside.txt")
        try fixture.createSymbolicLink(at: "artifact-link", destination: "outside.txt")
        try fixture.createSymbolicLink(at: "directory-link", destination: ".")
        try fixture.createDirectory(at: "artifact-directory")

        expectError(.artifactUnavailable) {
            try EvidenceArtifactHasher.hashInWorker(
                relativePaths: ["artifact-link"],
                repositoryRoot: fixture.directory
            )
        }
        expectError(.artifactNotRegularFile) {
            try EvidenceArtifactHasher.hashInWorker(
                relativePaths: ["artifact-directory"],
                repositoryRoot: fixture.directory
            )
        }
        expectError(.artifactUnavailable) {
            try EvidenceArtifactHasher.hashInWorker(
                relativePaths: ["directory-link/outside.txt"],
                repositoryRoot: fixture.directory
            )
        }
    }

    @Test("Oversized sparse artifacts fail without reading their payload")
    func rejectsOversizedArtifact() throws {
        let fixture = try TemporaryProfile(data: Data("{}".utf8))
        defer { expectSuccessfulRemoval(of: fixture) }
        try fixture.write(Data(), at: "oversized.bin")

        let artifactURL = fixture.directory.appendingPathComponent("oversized.bin")
        let descriptor = Darwin.open(artifactURL.path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC)
        try #require(descriptor >= 0)
        defer { Darwin.close(descriptor) }
        try #require(
            ftruncate(
                descriptor,
                off_t(EvidenceArtifactHasher.maximumArtifactBytes + 1)
            ) == 0
        )

        expectError(.artifactTooLarge) {
            try EvidenceArtifactHasher.hashInWorker(
                relativePaths: ["oversized.bin"],
                repositoryRoot: fixture.directory
            )
        }
    }

    @Test("Opened parent directories retain close-on-exec")
    func parentDirectoryIsCloseOnExec() throws {
        let fixture = try TemporaryProfile(data: Data("{}".utf8))
        defer { expectSuccessfulRemoval(of: fixture) }
        try fixture.write(Data("report".utf8), at: "reports/output.json")

        _ = try EvidenceArtifactHasher.hashInWorker(
            relativePaths: ["reports/output.json"],
            repositoryRoot: fixture.directory
        ) { _, _, parentDescriptor in
            let flags = Darwin.fcntl(parentDescriptor, F_GETFD)
            try #require(flags >= 0)
            #expect(flags & FD_CLOEXEC == FD_CLOEXEC)
        }
    }

    @Test("Atomic replacement during hashing fails closed")
    func rejectsAtomicReplacement() throws {
        let fixture = try TemporaryProfile(data: Data("{}".utf8))
        defer { expectSuccessfulRemoval(of: fixture) }
        try fixture.write(Data("old".utf8), at: "reports/output.json")

        expectError(.artifactChangedDuringRead) {
            try EvidenceArtifactHasher.hashInWorker(
                relativePaths: ["reports/output.json"],
                repositoryRoot: fixture.directory
            ) { _, _, parentDescriptor in
                let replacementDescriptor = Darwin.openat(
                    parentDescriptor,
                    "replacement.json",
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                    S_IRUSR | S_IWUSR
                )
                try #require(replacementDescriptor >= 0)
                defer { Darwin.close(replacementDescriptor) }
                let replacementBytes = Array("new".utf8)
                let writtenByteCount = replacementBytes.withUnsafeBytes { bytes in
                    Darwin.write(replacementDescriptor, bytes.baseAddress, bytes.count)
                }
                try #require(
                    writtenByteCount == replacementBytes.count
                )
                try #require(
                    "replacement.json".withCString { replacementName in
                        "output.json".withCString { outputName in
                            renameat(
                                parentDescriptor,
                                replacementName,
                                parentDescriptor,
                                outputName
                            )
                        }
                    } == 0
                )
            }
        }
    }

    @Test("Replacing an intermediate directory during hashing fails closed")
    func rejectsIntermediateDirectoryReplacement() throws {
        let fixture = try TemporaryProfile(data: Data("{}".utf8))
        defer { expectSuccessfulRemoval(of: fixture) }
        try fixture.write(Data("old".utf8), at: "reports/output.json")

        var replacedDirectory = false
        expectError(.artifactChangedDuringRead) {
            try EvidenceArtifactHasher.hashInWorker(
                relativePaths: ["reports/output.json"],
                repositoryRoot: fixture.directory
            ) { _, rootDescriptor, _ in
                try #require(
                    renameat(rootDescriptor, "reports", rootDescriptor, "old-reports") == 0
                )
                replacedDirectory = true
                try #require(
                    mkdirat(rootDescriptor, "reports", S_IRWXU) == 0
                )
                let reportsDescriptor = Darwin.openat(
                    rootDescriptor,
                    "reports",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
                )
                try #require(reportsDescriptor >= 0)
                defer { Darwin.close(reportsDescriptor) }
                let replacementDescriptor = Darwin.openat(
                    reportsDescriptor,
                    "output.json",
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                    S_IRUSR | S_IWUSR
                )
                try #require(replacementDescriptor >= 0)
                Darwin.close(replacementDescriptor)
            }
        }

        if replacedDirectory {
            do {
                try FileManager.default.removeItem(
                    at: fixture.directory.appendingPathComponent("reports")
                )
                try FileManager.default.moveItem(
                    at: fixture.directory.appendingPathComponent("old-reports"),
                    to: fixture.directory.appendingPathComponent("reports")
                )
            } catch {
                Issue.record("Intermediate-directory fixture restoration failed: \(error)")
            }
        }
    }

    @Test("Replacing the repository root during hashing fails closed")
    func rejectsRepositoryRootReplacement() throws {
        let fixture = try TemporaryProfile(data: Data("{}".utf8))
        defer { expectSuccessfulRemoval(of: fixture) }
        try fixture.write(Data("old".utf8), at: "reports/output.json")

        let fixtureParent = fixture.directory.deletingLastPathComponent()
        let fixtureParentDescriptor = Darwin.open(
            fixtureParent.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        try #require(fixtureParentDescriptor >= 0)
        defer { Darwin.close(fixtureParentDescriptor) }

        let fixtureName = fixture.directory.lastPathComponent
        let displacedName = "\(fixtureName)-displaced"
        var replacedRoot = false
        expectError(.artifactChangedDuringRead) {
            try EvidenceArtifactHasher.hashInWorker(
                relativePaths: ["reports/output.json"],
                repositoryRoot: fixture.directory
            ) { _, _, _ in
                try #require(
                    renameat(
                        fixtureParentDescriptor,
                        fixtureName,
                        fixtureParentDescriptor,
                        displacedName
                    ) == 0
                )
                replacedRoot = true
                try #require(
                    mkdirat(fixtureParentDescriptor, fixtureName, S_IRWXU) == 0
                )
            }
        }

        if replacedRoot {
            do {
                try FileManager.default.removeItem(at: fixture.directory)
                try FileManager.default.moveItem(
                    at: fixtureParent.appendingPathComponent(displacedName),
                    to: fixture.directory
                )
            } catch {
                Issue.record("Repository-root fixture restoration failed: \(error)")
            }
        }
    }

    private func expectSuccessfulRemoval(of fixture: TemporaryProfile) {
        do {
            try fixture.remove()
        } catch {
            Issue.record("Artifact fixture cleanup failed: \(error)")
        }
    }

    private func expectError(
        _ expectedCode: EvidenceArtifactHashingError.Code,
        operation: () throws -> [EvidenceArtifact]
    ) {
        do {
            _ = try operation()
            Issue.record("Expected artifact hashing to fail with \(expectedCode.rawValue).")
        } catch let error as EvidenceArtifactHashingError {
            #expect(error.code == expectedCode)
        } catch {
            Issue.record("Unexpected artifact hashing error: \(error)")
        }
    }
}
