import Foundation

public enum QualityMode: String, Codable, CaseIterable, Sendable {
    case `static` = "static"
    case build = "build"
    case buildAndTests = "build-and-tests"
    case full = "full"
}

public struct QualityModeStep: Codable, Sendable {
    public let id: String
    public let command: String
    public let action: PermissionAction?
    public let status: GateStatus
    public let applicability: String
    public let remediation: String

    public init(
        id: String,
        command: String,
        action: PermissionAction? = nil,
        status: GateStatus,
        applicability: String,
        remediation: String
    ) {
        self.id = id
        self.command = command
        self.action = action
        self.status = status
        self.applicability = applicability
        self.remediation = remediation
    }
}

public struct QualityModePlan: Codable, Sendable {
    public let schemaVersion: Int
    public let command: String
    public let mode: QualityMode
    public let status: GateStatus
    public let steps: [QualityModeStep]

    public init(mode: QualityMode, steps: [QualityModeStep]) {
        schemaVersion = 1
        command = "mode-plan"
        self.mode = mode
        self.steps = steps
        if steps.contains(where: { $0.status == .blocked }) {
            status = .blocked
        } else if steps.contains(where: { $0.status == .fail }) {
            status = .fail
        } else if steps.contains(where: { $0.status == .notRunByUserDecision }) {
            status = .notRunByUserDecision
        } else if steps.contains(where: { $0.status == .skipped }) {
            status = .skipped
        } else {
            status = .pass
        }
    }
}

public enum QualityModePlanner {
    public static func plan(profile: ProjectProfile, mode: QualityMode) -> QualityModePlan {
        var steps = [
            QualityModeStep(
                id: "QC.MODE.STATIC",
                command: "static-evidence",
                status: .notRunByUserDecision,
                applicability: "always",
                remediation: "Run the user-selected static evidence boundary."
            )
        ]

        guard mode != .static else {
            return QualityModePlan(mode: mode, steps: steps)
        }

        steps.append(
            QualityModeStep(
                id: "QC.MODE.BUILD",
                command: "build-evidence",
                action: .localBuildExecution,
                status: .notRunByUserDecision,
                applicability: "always",
                remediation: "Run the selected profile-declared Xcode build with explicit authority."
            )
        )

        guard mode == .buildAndTests || mode == .full else {
            return QualityModePlan(mode: mode, steps: steps)
        }

        steps.append(testStep(for: profile))
        steps.append(capabilityStep(
            id: "QC.MODE.SNAPSHOT_TESTS",
            command: "snapshot-tests",
            action: .localTestExecution,
            capability: .snapshotTests,
            profile: profile,
            remediation: "Run only with explicit test permission and bind snapshot-test evidence."
        ))

        guard mode == .full else {
            return QualityModePlan(mode: mode, steps: steps)
        }

        steps.append(capabilityStep(
            id: "QC.MODE.UI_TESTS",
            command: "ui-tests",
            action: .uiTests,
            capability: .uiTests,
            profile: profile,
            remediation: "Record explicit NOT_APPLICABLE or obtain permission before running UI tests."
        ))
        steps.append(capabilityStep(
            id: "QC.MODE.ARCHIVE_SIGNING",
            command: "archive-signing",
            capability: .archiveSigning,
            profile: profile,
            remediation: "Record explicit NOT_APPLICABLE or add the release-purpose archive/signing boundary."
        ))
        steps.append(capabilityStep(
            id: "QC.MODE.FEATURE_FLAGS",
            command: "feature-flags-review",
            capability: .featureFlags,
            profile: profile,
            remediation: "Record safe defaults, owner, expiry, rollout, and rollback, or explicit NOT_APPLICABLE."
        ))
        steps.append(capabilityStep(
            id: "QC.MODE.PRIVACY",
            command: "privacy-review",
            capability: .privacy,
            profile: profile,
            remediation: "Review privacy applicability and reconcile manifests, labels, and data lifecycle."
        ))
        steps.append(capabilityStep(
            id: "QC.MODE.OBSERVABILITY",
            command: "observability-review",
            capability: .observability,
            profile: profile,
            remediation: "Review observability applicability and record safe, privacy-preserving telemetry boundaries."
        ))
        steps.append(capabilityStep(
            id: "QC.MODE.PLATFORM_CAPABILITIES",
            command: "platform-capabilities-review",
            action: .simulatorOrDevice,
            capability: .platformCapabilities,
            profile: profile,
            remediation: "Review platform-capability applicability and bind any Simulator/device evidence separately."
        ))
        return QualityModePlan(mode: mode, steps: steps)
    }

    private static func testStep(for profile: ProjectProfile) -> QualityModeStep {
        guard let applicability = profile.applicability?.first(where: { $0.capability == .tests }) else {
            return QualityModeStep(
                id: "QC.MODE.TESTS",
                command: "xcode-tests",
                action: .localTestExecution,
                status: .blocked,
                applicability: "unknown",
                remediation: "Add an explicit tests applicability record before selecting build-and-tests."
            )
        }
        let outcome = applicabilityOutcome(
            applicability: applicability,
            action: .localTestExecution,
            profile: profile,
            applicableRemediation: "Run only with explicit test permission and bind terminal test evidence."
        )
        return QualityModeStep(
            id: "QC.MODE.TESTS",
            command: "xcode-tests",
            action: .localTestExecution,
            status: outcome.status,
            applicability: applicability.status.rawValue,
            remediation: outcome.remediation
        )
    }

    private static func capabilityStep(
        id: String,
        command: String,
        action: PermissionAction? = nil,
        capability: CapabilityID,
        profile: ProjectProfile,
        remediation: String
    ) -> QualityModeStep {
        guard let applicability = profile.applicability?.first(where: { $0.capability == capability }) else {
            return QualityModeStep(
                id: id,
                command: command,
                action: action,
                status: .blocked,
                applicability: "unknown",
                remediation: "Add an explicit applicability record for \(capability.rawValue)."
            )
        }
        let outcome = applicabilityOutcome(
            applicability: applicability,
            action: action,
            profile: profile,
            applicableRemediation: remediation
        )
        return QualityModeStep(
            id: id,
            command: command,
            action: action,
            status: outcome.status,
            applicability: applicability.status.rawValue,
            remediation: outcome.remediation
        )
    }

    private static func applicabilityOutcome(
        applicability: CapabilityApplicability,
        action: PermissionAction?,
        profile: ProjectProfile,
        applicableRemediation: String
    ) -> (status: GateStatus, remediation: String) {
        switch applicability.status {
        case .applicable:
            if let action,
               PermissionEvaluator.requirement(for: action, policy: profile.permissions) == .prohibited {
                return (
                    .blocked,
                    "The profile prohibits \(action.rawValue); no execution may be attempted."
                )
            }
            return (.notRunByUserDecision, applicableRemediation)
        case .notApplicable:
            return (
                .notApplicable,
                "Not applicable: \(applicability.reason) Revisit condition: \(applicability.revisitCondition)."
            )
        case .deferred:
            return (
                .notRunByUserDecision,
                "Deferred: \(applicability.reason) Owner: \(applicability.owner). Revisit condition: \(applicability.revisitCondition)."
            )
        }
    }
}
