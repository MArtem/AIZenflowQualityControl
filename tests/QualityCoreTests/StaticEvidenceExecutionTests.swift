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
}
