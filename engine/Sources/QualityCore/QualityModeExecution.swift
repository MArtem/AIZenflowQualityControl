import Foundation

/// One bounded child result observed while executing a manual quality mode.
///
/// Child evidence remains attached to the child step. The mode envelope never synthesizes a
/// composite evidence claim from status alone; callers that need one must use the explicit
/// `aggregate-evidence` boundary with a caller-owned trusted expectation.
public struct QualityModeExecutionStep: Encodable, Sendable {
    public let id: String
    public let command: String
    public let status: GateStatus
    public let message: String
    public let report: QualityReport?
    public let evidence: QualityEvidence?
    public let verification: EvidenceVerification?

    public init(
        id: String,
        command: String,
        status: GateStatus,
        message: String,
        report: QualityReport? = nil,
        evidence: QualityEvidence? = nil,
        verification: EvidenceVerification? = nil
    ) {
        self.id = id
        self.command = command
        self.status = status
        self.message = message
        self.report = report
        self.evidence = evidence
        self.verification = verification
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case command
        case status
        case message
        case report
        case evidence
        case verification
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(command, forKey: .command)
        try container.encode(status, forKey: .status)
        try container.encode(message, forKey: .message)
        if let report {
            try container.encode(report, forKey: .report)
        } else {
            try container.encodeNil(forKey: .report)
        }
        if let evidence {
            try container.encode(evidence, forKey: .evidence)
        } else {
            try container.encodeNil(forKey: .evidence)
        }
        if let verification {
            try container.encode(verification, forKey: .verification)
        } else {
            try container.encodeNil(forKey: .verification)
        }
    }
}

/// Versioned result for one user-selected manual quality mode.
///
/// `PASS` means every required step executed and passed, while `NOT_RUN_BY_USER_DECISION` and
/// `SKIPPED` remain terminal non-success states. This envelope intentionally has no top-level
/// evidence field: individual child receipts are the proof, and a composite proof requires the
/// separate expectation-bound aggregation command.
public struct QualityModeExecutionResult: Encodable, Sendable {
    public static let currentSchemaVersion = 1
    public let schemaVersion: Int
    public let command: String
    public let mode: QualityMode
    public let status: GateStatus
    public let steps: [QualityModeExecutionStep]

    public init(mode: QualityMode, steps: [QualityModeExecutionStep]) {
        schemaVersion = Self.currentSchemaVersion
        command = "mode-execute"
        self.mode = mode
        let normalizedSteps = steps.isEmpty ? [QualityModeExecutionStep(
            id: "QC.MODE.EXECUTION.EMPTY",
            command: "mode-execute",
            status: .blocked,
            message: "A mode execution result cannot be emitted without at least one step."
        )] : steps
        self.steps = normalizedSteps
        if normalizedSteps.contains(where: { $0.status == .blocked }) {
            status = .blocked
        } else if normalizedSteps.contains(where: { $0.status == .fail }) {
            status = .fail
        } else if normalizedSteps.contains(where: { $0.status == .notRunByUserDecision }) {
            status = .notRunByUserDecision
        } else if normalizedSteps.contains(where: { $0.status == .skipped }) {
            status = .skipped
        } else {
            status = .pass
        }
    }
}
