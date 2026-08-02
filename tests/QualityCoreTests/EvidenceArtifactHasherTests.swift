import Darwin
import Foundation
import Testing
@testable import QualityCore

@Suite("Evidence artifact hashing")
struct EvidenceArtifactHasherTests {
    @Test("An empty artifact set needs no filesystem access")
    func acceptsEmptyArtifactSet() throws {
        let artifacts = try EvidenceArtifactHasher.hash(
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

        let artifacts = try EvidenceArtifactHasher.hash(
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
            "./file"
        ]
    )
    func rejectsUnsafePath(_ path: String) throws {
        let fixture = try TemporaryProfile(data: Data("{}".utf8))
        defer { expectSuccessfulRemoval(of: fixture) }

        expectError(.invalidPath) {
            try EvidenceArtifactHasher.hash(
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
            try EvidenceArtifactHasher.hash(
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
            try EvidenceArtifactHasher.hash(
                relativePaths: ["report.json", "report.json"],
                repositoryRoot: fixture.directory
            )
        }
        expectError(.tooManyArtifacts) {
            try EvidenceArtifactHasher.hash(
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
            try EvidenceArtifactHasher.hash(
                relativePaths: ["artifact-link"],
                repositoryRoot: fixture.directory
            )
        }
        expectError(.artifactNotRegularFile) {
            try EvidenceArtifactHasher.hash(
                relativePaths: ["artifact-directory"],
                repositoryRoot: fixture.directory
            )
        }
        expectError(.artifactUnavailable) {
            try EvidenceArtifactHasher.hash(
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
            try EvidenceArtifactHasher.hash(
                relativePaths: ["oversized.bin"],
                repositoryRoot: fixture.directory
            )
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
