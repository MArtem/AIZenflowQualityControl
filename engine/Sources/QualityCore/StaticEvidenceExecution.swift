import CryptoKit
import Foundation

package enum StaticEvidenceResultLimits {
    package static let maximumChecks = 2_048
    package static let maximumStringScalars = 1_024
}

/// Exact, descriptor-pinned inputs observed by the public static-evidence boundary.
package struct StaticEvidenceInputSnapshots: Sendable {
    package static let maximumInputBytes = 1_000_000
    package let profileSnapshot: ProfileSnapshot
    package let profileData: Data
    package let policyData: Data
    package let policySHA256: String

    package static func load(profileURL: URL, policyURL: URL) throws -> Self {
        let policyData = try JSONDocumentConstraints.loadData(from: policyURL)
        return try Self.load(profileURL: profileURL, policyData: policyData)
    }

    package static func load(profileURL: URL, policyData: Data) throws -> Self {
        let profileData = try JSONDocumentConstraints.loadData(from: profileURL)
        return try Self(profileData: profileData, policyData: policyData)
    }

    package init(profileData: Data, policyData: Data) throws {
        let profileSnapshot = try ProfileSnapshot(data: profileData)
        guard policyData.count <= JSONDocumentConstraints.maximumBytes else {
            throw GitTreeStaticSnapshotError.limitExceeded
        }
        try JSONDocumentConstraints.rejectDuplicateObjectKeys(in: policyData)
        self.profileSnapshot = profileSnapshot
        self.profileData = profileData
        self.policyData = policyData
        policySHA256 = SHA256.hash(data: policyData).map { String(format: "%02x", $0) }.joined()
    }
}

/// Versioned public result of one static-evidence execution.
///
/// Evidence is included only after the coordinator and verifier agree. A preflight or process
/// boundary failure therefore has no evidence payload that a consumer could mistake for proof.
public struct StaticEvidenceExecutionResult: Encodable, Sendable {
    public static let currentSchemaVersion = 1
    public let schemaVersion: Int
    public let command: String
    public let status: QualityStatus
    public let report: QualityReport
    public let evidence: QualityEvidence?
    public let verification: EvidenceVerification?

    package init(report: QualityReport) {
        schemaVersion = Self.currentSchemaVersion
        command = "static-evidence"
        if report.command != "static" || report.status == .pass {
            self.report = QualityReport(
                command: "static",
                checks: [
                    QualityCheck(
                        id: "QC.STATIC_EVIDENCE.UNVERIFIED_PASS",
                        status: .blocked,
                        message: "An unverified static PASS cannot be emitted as static evidence."
                    )
                ]
            )
            status = .blocked
        } else {
            self.report = report
            status = report.status
        }
        evidence = nil
        verification = nil
    }

    package init(receipt: StaticEvidenceReceipt) {
        schemaVersion = Self.currentSchemaVersion
        command = "static-evidence"
        status = receipt.report.status
        report = receipt.report
        evidence = receipt.evidence
        verification = receipt.verification
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case command
        case status
        case report
        case evidence
        case verification
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(command, forKey: .command)
        try container.encode(status, forKey: .status)
        try container.encode(report, forKey: .report)
        if let evidence, let verification {
            try container.encode(evidence, forKey: .evidence)
            try container.encode(verification, forKey: .verification)
        } else {
            try container.encodeNil(forKey: .evidence)
            try container.encodeNil(forKey: .verification)
        }
    }
}
