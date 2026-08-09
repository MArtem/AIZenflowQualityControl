import Foundation
import Testing
@testable import QualityCore

@Suite("Static evidence execution envelope")
struct StaticEvidenceExecutionTests {
    @Test("An unverified worker PASS is converted to BLOCKED without evidence")
    func unverifiedPassFailsClosed() {
        let result = StaticEvidenceExecutionResult(
            report: QualityReport(
                command: "static",
                checks: [QualityCheck(id: "QC.STATIC.SCAN", status: .pass, message: "Passed.")]
            )
        )

        #expect(result.schemaVersion == 1)
        #expect(result.command == "static-evidence")
        #expect(result.status == .blocked)
        #expect(result.report.status == .blocked)
        #expect(result.evidence == nil)
        #expect(result.verification == nil)
    }

    @Test("A non-pass boundary result remains evidence-free and preserves its status")
    func nonPassResultRemainsEvidenceFree() {
        let result = StaticEvidenceExecutionResult(
            report: QualityReport(
                command: "static",
                checks: [QualityCheck(id: "QC.STATIC.FAILURE", status: .fail, message: "Failed.")]
            )
        )

        #expect(result.status == .fail)
        #expect(result.evidence == nil)
        #expect(result.verification == nil)
    }

    @Test("A Git tree manifest materializes scanner metadata without reading the mutable worktree")
    func gitTreeManifestMaterializesSparseFilesAndSymlinks() throws {
        let snapshot = try GitTreeStaticSnapshot(
            manifest: Data(
                """
                100644 blob 0123456789012345678901234567890123456789 12\tSources/Safe.swift\0
                120000 blob 0123456789012345678901234567890123456789 4\tSources/Link.swift\0
                """.utf8
            )
        )
        let fixture = try TemporaryProfile(data: Data("{}".utf8))
        defer { try? GitTreeStaticSnapshot.removeMaterialization(at: fixture.directory.appendingPathComponent("snapshot")) }
        defer { try? fixture.remove() }
        try fixture.createDirectory(at: "snapshot")

        let root = try snapshot.materialize(
            in: fixture.directory.appendingPathComponent("snapshot"),
            sourcePaths: ["Sources"]
        )
        defer { try? GitTreeStaticSnapshot.removeMaterialization(at: root) }
        let file = root.appendingPathComponent("Sources/Safe.swift")
        let values = try file.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
        #expect(values.isRegularFile == true)
        #expect(values.fileSize == 12)
        let linkTarget = try FileManager.default.destinationOfSymbolicLink(
            atPath: root.appendingPathComponent("Sources/Link.swift").path
        )
        #expect(linkTarget == "git-tree-snapshot")
    }
}
