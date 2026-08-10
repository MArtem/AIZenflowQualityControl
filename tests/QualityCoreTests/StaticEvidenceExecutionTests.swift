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

    @Test("A Git tree manifest reports metadata without projecting onto a filesystem")
    func gitTreeManifestScansMetadataDirectly() throws {
        let snapshot = try GitTreeStaticSnapshot(
            manifest: Data(
                """
                100644 blob 0123456789012345678901234567890123456789 12\tSources/Safe.swift\0
                120000 blob 0123456789012345678901234567890123456789 4\tSources/Link.swift\0
                """.utf8
            )
        )
        let checks = snapshot.staticChecks(
            sourcePaths: ["Sources"],
            maximumFileBytes: 16,
            excludedDirectoryNames: [],
            forbiddenFileSuffixes: [".xcresult"]
        )
        #expect(checks.map(\.id) == ["QC.STATIC.SYMLINK_REQUIRES_REVIEW"])
    }

    @Test("Filesystem-equivalent Git paths are rejected before scanning")
    func gitTreeManifestRejectsCaseCollisions() {
        let manifest = Data(
            (
                "100644 blob 0123456789012345678901234567890123456789 1\tSources/Safe.swift\0"
                + "100644 blob 0123456789012345678901234567890123456789 9\tSources/safe.swift\0"
            ).utf8
        )
        #expect(throws: GitTreeStaticSnapshotError.self) {
            try GitTreeStaticSnapshot(manifest: manifest)
        }
    }

    @Test("Forbidden artifact directory components fail manifest scanning")
    func gitTreeManifestRejectsForbiddenDirectory() throws {
        let snapshot = try GitTreeStaticSnapshot(
            manifest: Data("100644 blob 0123456789012345678901234567890123456789 1\tSources/App.xcarchive/Info.plist\0".utf8)
        )
        let checks = snapshot.staticChecks(
            sourcePaths: ["Sources"],
            maximumFileBytes: 16,
            excludedDirectoryNames: [],
            forbiddenFileSuffixes: [".xcarchive"]
        )
        #expect(checks.map(\.id) == ["QC.STATIC.FORBIDDEN_ARTIFACT"])
    }

    @Test("Manifest findings reserve the worker response byte envelope")
    func manifestFindingsRespectEncodedResponseBudget() throws {
        let manifest = (0..<1_500).map { index in
            let path = "Sources/" + String(repeating: "\u{0001}", count: 1_001)
                + "-" + String(format: "%04d", index) + ".xcarchive"
            return "100644 blob 0123456789012345678901234567890123456789 1\t\(path)\0"
        }.joined()
        let snapshot = try GitTreeStaticSnapshot(manifest: Data(manifest.utf8))

        let checks = snapshot.staticChecks(
            sourcePaths: ["Sources"],
            maximumFileBytes: 16,
            excludedDirectoryNames: [],
            forbiddenFileSuffixes: [".xcarchive"]
        )

        #expect(checks.last?.id == "QC.STATIC.SCAN_LIMIT_REACHED")
        #expect(checks.count < StaticEvidenceResultLimits.maximumChecks - 3)
    }
}
