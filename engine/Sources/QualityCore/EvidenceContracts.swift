import Foundation

public enum PermissionAction: String, Codable, CaseIterable, Sendable {
    case testCreation
    case testModification
    case localTestExecution
    case githubExecution
    case uiTests
    case simulatorOrDevice
    case performanceOrInstruments
}

public enum PermissionRequirement: String, Codable, Equatable, Sendable {
    case authorizedByProfile = "AUTHORIZED_BY_PROFILE"
    case userAuthorizationRequired = "USER_AUTHORIZATION_REQUIRED"
    case prohibited = "PROHIBITED"
}

public enum PermissionEvaluator {
    public static func requirement(
        for action: PermissionAction,
        policy: PermissionPolicy
    ) -> PermissionRequirement {
        switch action {
        case .testCreation:
            return requirement(for: policy.testCreation)
        case .testModification:
            return requirement(for: policy.testModification)
        case .localTestExecution:
            return requirement(for: policy.localTestExecution)
        case .githubExecution:
            switch policy.githubExecution {
            case .off:
                return .prohibited
            case .manual:
                return .userAuthorizationRequired
            }
        case .uiTests:
            return requirement(for: policy.uiTests)
        case .simulatorOrDevice:
            return requirement(for: policy.simulatorOrDevice)
        case .performanceOrInstruments:
            return requirement(for: policy.performanceOrInstruments)
        }
    }

    private static func requirement(
        for decision: PermissionDecision
    ) -> PermissionRequirement {
        switch decision {
        case .allow:
            return .authorizedByProfile
        case .ask:
            return .userAuthorizationRequired
        case .deny:
            return .prohibited
        }
    }
}

public enum GateStatus: String, Codable, CaseIterable, Sendable {
    case pass = "PASS"
    case fail = "FAIL"
    case blocked = "BLOCKED"
    case notApplicable = "NOT_APPLICABLE"
    case notRunByUserDecision = "NOT_RUN_BY_USER_DECISION"
    case skipped = "SKIPPED"
}

public enum AdvisoryVerdict: String, Codable, Equatable, Sendable {
    case ready = "READY"
    case readyWithAcceptedRisk = "READY_WITH_ACCEPTED_RISK"
    case needsOwnerDecision = "NEEDS_OWNER_DECISION"
    case notReady = "NOT_READY"
    case blocked = "BLOCKED"
    case bypassed = "BYPASSED"
}

public enum EvidenceAuthorization: String, Codable, Sendable {
    case notRequired = "NOT_REQUIRED"
    case profile = "PROFILE"
    case user = "USER"
}

public struct EvidenceToolchain: Codable, Equatable, Sendable {
    public let swiftVersion: String
    public let xcodeVersion: String

    public init(swiftVersion: String, xcodeVersion: String) {
        self.swiftVersion = swiftVersion
        self.xcodeVersion = xcodeVersion
    }
}

public struct EvidenceCommand: Codable, Sendable {
    public let id: String
    public let commandLine: [String]
    public let exitCode: Int?
    public let action: PermissionAction?
    public let authorization: EvidenceAuthorization

    public init(
        id: String,
        commandLine: [String],
        exitCode: Int?,
        action: PermissionAction? = nil,
        authorization: EvidenceAuthorization = .notRequired
    ) {
        self.id = id
        self.commandLine = commandLine
        self.exitCode = exitCode
        self.action = action
        self.authorization = authorization
    }
}

public struct EvidenceGate: Codable, Sendable {
    public let id: String
    public let status: GateStatus
    public let message: String
    public let commandID: String?
    public let action: PermissionAction?

    public init(
        id: String,
        status: GateStatus,
        message: String,
        commandID: String? = nil,
        action: PermissionAction? = nil
    ) {
        self.id = id
        self.status = status
        self.message = message
        self.commandID = commandID
        self.action = action
    }
}

public struct EvidenceTestCounts: Codable, Equatable, Sendable {
    public let total: Int
    public let passed: Int
    public let failed: Int
    public let skipped: Int

    public init(total: Int, passed: Int, failed: Int, skipped: Int) {
        self.total = total
        self.passed = passed
        self.failed = failed
        self.skipped = skipped
    }
}

public struct EvidenceArtifact: Codable, Sendable {
    public let path: String
    public let sha256: String

    public init(path: String, sha256: String) {
        self.path = path
        self.sha256 = sha256
    }
}

public struct QualityEvidence: Codable, Sendable {
    public let schemaVersion: Int
    public let sourceRepository: String
    public let sourceRevision: String
    public let engineVersion: String
    public let engineRevision: String
    public let profileSchemaVersion: Int
    public let profileSHA256: String
    public let toolchain: EvidenceToolchain
    public let permissions: PermissionPolicy
    public let commands: [EvidenceCommand]
    public let gates: [EvidenceGate]
    public let testCounts: EvidenceTestCounts?
    public let reviewRevision: String?
    public let artifacts: [EvidenceArtifact]
    public let residualRisks: [String]
    public let claimedVerdict: AdvisoryVerdict

    public init(
        schemaVersion: Int = 1,
        sourceRepository: String,
        sourceRevision: String,
        engineVersion: String,
        engineRevision: String,
        profileSchemaVersion: Int,
        profileSHA256: String,
        toolchain: EvidenceToolchain,
        permissions: PermissionPolicy,
        commands: [EvidenceCommand],
        gates: [EvidenceGate],
        testCounts: EvidenceTestCounts? = nil,
        reviewRevision: String? = nil,
        artifacts: [EvidenceArtifact] = [],
        residualRisks: [String] = [],
        claimedVerdict: AdvisoryVerdict
    ) {
        self.schemaVersion = schemaVersion
        self.sourceRepository = sourceRepository
        self.sourceRevision = sourceRevision
        self.engineVersion = engineVersion
        self.engineRevision = engineRevision
        self.profileSchemaVersion = profileSchemaVersion
        self.profileSHA256 = profileSHA256
        self.toolchain = toolchain
        self.permissions = permissions
        self.commands = commands
        self.gates = gates
        self.testCounts = testCounts
        self.reviewRevision = reviewRevision
        self.artifacts = artifacts
        self.residualRisks = residualRisks
        self.claimedVerdict = claimedVerdict
    }
}

public struct EvidenceCommandExpectation: Equatable, Sendable {
    public let commandLine: [String]
    public let action: PermissionAction?

    public init(commandLine: [String], action: PermissionAction? = nil) {
        self.commandLine = commandLine
        self.action = action
    }
}

public struct EvidenceGateExpectation: Equatable, Sendable {
    public let commandID: String?
    public let action: PermissionAction?

    public init(commandID: String? = nil, action: PermissionAction? = nil) {
        self.commandID = commandID
        self.action = action
    }
}

public struct EvidenceExpectation: Sendable {
    public let sourceRepository: String
    public let sourceRevision: String
    public let engineVersion: String
    public let engineRevision: String
    public let profileSchemaVersion: Int
    public let profileSHA256: String
    public let toolchain: EvidenceToolchain
    public let permissions: PermissionPolicy
    public let commandsByID: [String: EvidenceCommandExpectation]
    public let gatesByID: [String: EvidenceGateExpectation]
    public let userAuthorizedActions: Set<PermissionAction>
    public let testCounts: EvidenceTestCounts?
    public let testGateID: String?
    public let reviewRevision: String?
    public let artifactSHA256ByPath: [String: String]
    public let residualRisks: Set<String>

    public init(
        sourceRepository: String,
        sourceRevision: String,
        engineVersion: String,
        engineRevision: String,
        profileSchemaVersion: Int,
        profileSHA256: String,
        toolchain: EvidenceToolchain,
        permissions: PermissionPolicy,
        commandsByID: [String: EvidenceCommandExpectation],
        gatesByID: [String: EvidenceGateExpectation],
        userAuthorizedActions: Set<PermissionAction> = [],
        testCounts: EvidenceTestCounts? = nil,
        testGateID: String? = nil,
        reviewRevision: String? = nil,
        artifactSHA256ByPath: [String: String] = [:],
        residualRisks: Set<String> = []
    ) {
        self.sourceRepository = sourceRepository
        self.sourceRevision = sourceRevision
        self.engineVersion = engineVersion
        self.engineRevision = engineRevision
        self.profileSchemaVersion = profileSchemaVersion
        self.profileSHA256 = profileSHA256
        self.toolchain = toolchain
        self.permissions = permissions
        self.commandsByID = commandsByID
        self.gatesByID = gatesByID
        self.userAuthorizedActions = userAuthorizedActions
        self.testCounts = testCounts
        self.testGateID = testGateID
        self.reviewRevision = reviewRevision
        self.artifactSHA256ByPath = artifactSHA256ByPath
        self.residualRisks = residualRisks
    }
}

public struct EvidenceVerificationIssue: Codable, Equatable, Sendable {
    public let code: String
    public let message: String

    public init(code: String, message: String) {
        self.code = code
        self.message = message
    }
}

public struct EvidenceVerification: Codable, Sendable {
    public let verdict: AdvisoryVerdict
    public let issues: [EvidenceVerificationIssue]

    public init(verdict: AdvisoryVerdict, issues: [EvidenceVerificationIssue]) {
        self.verdict = verdict
        self.issues = issues
    }
}

public enum EvidenceVerifier {
    public static func verify(
        _ evidence: QualityEvidence,
        expected: EvidenceExpectation
    ) -> EvidenceVerification {
        var issues: [EvidenceVerificationIssue] = []

        require(evidence.schemaVersion == 1, "QC.EVIDENCE.UNSUPPORTED_SCHEMA", &issues)
        require(
            !evidence.sourceRepository.isEmpty
                && evidence.sourceRepository == expected.sourceRepository,
            "QC.EVIDENCE.SOURCE_REPOSITORY_MISMATCH",
            &issues
        )
        validateRevision(evidence.sourceRevision, code: "QC.EVIDENCE.INVALID_SOURCE_REVISION", &issues)
        require(
            evidence.sourceRevision == expected.sourceRevision,
            "QC.EVIDENCE.STALE_SOURCE_REVISION",
            &issues
        )
        require(
            !evidence.engineVersion.isEmpty && evidence.engineVersion == expected.engineVersion,
            "QC.EVIDENCE.ENGINE_VERSION_MISMATCH",
            &issues
        )
        validateRevision(evidence.engineRevision, code: "QC.EVIDENCE.INVALID_ENGINE_REVISION", &issues)
        require(
            evidence.engineRevision == expected.engineRevision,
            "QC.EVIDENCE.ENGINE_REVISION_MISMATCH",
            &issues
        )
        require(
            evidence.profileSchemaVersion == expected.profileSchemaVersion,
            "QC.EVIDENCE.PROFILE_SCHEMA_MISMATCH",
            &issues
        )
        validateSHA256(evidence.profileSHA256, code: "QC.EVIDENCE.INVALID_PROFILE_HASH", &issues)
        require(
            evidence.profileSHA256 == expected.profileSHA256,
            "QC.EVIDENCE.PROFILE_HASH_MISMATCH",
            &issues
        )
        require(
            evidence.toolchain == expected.toolchain
                && !evidence.toolchain.swiftVersion.isEmpty
                && !evidence.toolchain.xcodeVersion.isEmpty,
            "QC.EVIDENCE.TOOLCHAIN_MISMATCH",
            &issues
        )
        require(
            evidence.permissions == expected.permissions,
            "QC.EVIDENCE.PERMISSION_SNAPSHOT_MISMATCH",
            &issues
        )

        validateBounds(evidence, issues: &issues)
        validateCommands(
            evidence.commands,
            policy: evidence.permissions,
            expectedByID: expected.commandsByID,
            userAuthorizedActions: expected.userAuthorizedActions,
            issues: &issues
        )
        validateGates(
            evidence.gates,
            commands: evidence.commands,
            expectedByID: expected.gatesByID,
            issues: &issues
        )
        validateTestCounts(
            evidence.testCounts,
            gates: evidence.gates,
            expectedTestGateID: expected.testGateID,
            issues: &issues
        )
        require(
            evidence.testCounts == expected.testCounts,
            "QC.EVIDENCE.TEST_COUNTS_MISMATCH",
            &issues
        )
        validateReviewRevision(evidence.reviewRevision, sourceRevision: evidence.sourceRevision, issues: &issues)
        require(
            evidence.reviewRevision == expected.reviewRevision,
            "QC.EVIDENCE.REVIEW_REVISION_MISMATCH",
            &issues
        )
        validateArtifacts(
            evidence.artifacts,
            expected: expected.artifactSHA256ByPath,
            issues: &issues
        )
        require(
            Set(evidence.residualRisks) == expected.residualRisks
                && Set(evidence.residualRisks).count == evidence.residualRisks.count,
            "QC.EVIDENCE.RESIDUAL_RISK_MISMATCH",
            &issues
        )

        let derivedVerdict = aggregate(evidence.gates)
        require(
            evidence.claimedVerdict == derivedVerdict,
            "QC.EVIDENCE.CLAIMED_VERDICT_MISMATCH",
            &issues
        )

        guard issues.isEmpty else {
            return EvidenceVerification(verdict: .bypassed, issues: issues)
        }
        return EvidenceVerification(verdict: derivedVerdict, issues: [])
    }

    public static func aggregate(_ gates: [EvidenceGate]) -> AdvisoryVerdict {
        guard !gates.isEmpty else {
            return .blocked
        }
        if gates.contains(where: { $0.status == .fail }) {
            return .notReady
        }
        if gates.contains(where: { $0.status == .blocked || $0.status == .skipped }) {
            return .blocked
        }
        if gates.contains(where: { $0.status == .notRunByUserDecision }) {
            return .needsOwnerDecision
        }
        if gates.contains(where: { $0.status == .pass }) {
            return .ready
        }
        return .blocked
    }

    private static func validateCommands(
        _ commands: [EvidenceCommand],
        policy: PermissionPolicy,
        expectedByID: [String: EvidenceCommandExpectation],
        userAuthorizedActions: Set<PermissionAction>,
        issues: inout [EvidenceVerificationIssue]
    ) {
        require(!commands.isEmpty, "QC.EVIDENCE.NO_COMMANDS", &issues)
        require(
            Set(commands.map(\.id)).count == commands.count,
            "QC.EVIDENCE.DUPLICATE_COMMAND_ID",
            &issues
        )
        require(
            commands.count == expectedByID.count
                && expectedByID.allSatisfy { id, expectation in
                    commands.contains {
                        $0.id == id
                            && $0.commandLine == expectation.commandLine
                            && $0.action == expectation.action
                    }
                },
            "QC.EVIDENCE.COMMAND_SET_MISMATCH",
            &issues
        )

        for command in commands {
            require(
                !command.id.isEmpty && !command.commandLine.isEmpty
                    && command.commandLine.allSatisfy { !$0.isEmpty }
                    && command.exitCode.map { (0...255).contains($0) } != false,
                "QC.EVIDENCE.INVALID_COMMAND",
                &issues
            )

            guard let action = command.action else {
                require(
                    command.authorization == .notRequired,
                    "QC.EVIDENCE.UNEXPECTED_COMMAND_AUTHORIZATION",
                    &issues
                )
                continue
            }

            switch PermissionEvaluator.requirement(for: action, policy: policy) {
            case .authorizedByProfile:
                require(
                    command.authorization == .profile,
                    "QC.EVIDENCE.INVALID_PROFILE_AUTHORIZATION",
                    &issues
                )
            case .userAuthorizationRequired:
                require(
                    command.authorization == .user && userAuthorizedActions.contains(action),
                    "QC.EVIDENCE.MISSING_USER_AUTHORIZATION",
                    &issues
                )
            case .prohibited:
                require(false, "QC.EVIDENCE.PROHIBITED_COMMAND_EXECUTED", &issues)
            }
        }
    }

    private static func validateGates(
        _ gates: [EvidenceGate],
        commands: [EvidenceCommand],
        expectedByID: [String: EvidenceGateExpectation],
        issues: inout [EvidenceVerificationIssue]
    ) {
        require(!gates.isEmpty, "QC.EVIDENCE.NO_GATES", &issues)
        require(
            Set(gates.map(\.id)).count == gates.count,
            "QC.EVIDENCE.DUPLICATE_GATE_ID",
            &issues
        )
        require(
            gates.count == expectedByID.count
                && expectedByID.allSatisfy { id, expectation in
                    gates.contains {
                        $0.id == id
                            && $0.commandID == expectation.commandID
                            && $0.action == expectation.action
                    }
                },
            "QC.EVIDENCE.GATE_SET_MISMATCH",
            &issues
        )
        let commandIDs = Set(commands.map(\.id))

        for gate in gates {
            require(
                !gate.id.isEmpty && !gate.message.isEmpty,
                "QC.EVIDENCE.INVALID_GATE",
                &issues
            )
            if let commandID = gate.commandID {
                require(
                    commandIDs.contains(commandID),
                    "QC.EVIDENCE.UNKNOWN_GATE_COMMAND",
                    &issues
                )
            }
            if gate.status == .pass || gate.status == .fail {
                require(
                    gate.commandID != nil,
                    "QC.EVIDENCE.EXECUTED_GATE_WITHOUT_COMMAND",
                    &issues
                )
            }
            if let commandID = gate.commandID,
               let command = commands.first(where: { $0.id == commandID }) {
                require(
                    gate.action == command.action,
                    "QC.EVIDENCE.GATE_ACTION_MISMATCH",
                    &issues
                )
                if gate.status == .pass {
                    require(
                        command.exitCode == 0,
                        "QC.EVIDENCE.PASS_EXIT_CODE_MISMATCH",
                        &issues
                    )
                } else if gate.status == .fail {
                    require(
                        command.exitCode != nil && command.exitCode != 0,
                        "QC.EVIDENCE.FAIL_EXIT_CODE_MISMATCH",
                        &issues
                    )
                }
            }
            if gate.status == .notApplicable
                || gate.status == .notRunByUserDecision
                || gate.status == .skipped {
                require(
                    gate.commandID == nil,
                    "QC.EVIDENCE.NON_EXECUTED_GATE_WITH_COMMAND",
                    &issues
                )
            }
            if gate.status == .notRunByUserDecision {
                require(
                    gate.action != nil,
                    "QC.EVIDENCE.USER_DECISION_WITHOUT_ACTION",
                    &issues
                )
            }
        }
    }

    private static func validateTestCounts(
        _ counts: EvidenceTestCounts?,
        gates: [EvidenceGate],
        expectedTestGateID: String?,
        issues: inout [EvidenceVerificationIssue]
    ) {
        guard let counts else {
            require(
                expectedTestGateID == nil,
                "QC.EVIDENCE.TEST_GATE_WITHOUT_COUNTS",
                &issues
            )
            return
        }
        let maximumCount = 1_000_000
        let components = [counts.total, counts.passed, counts.failed, counts.skipped]
        let componentsAreBounded = components.allSatisfy { (0...maximumCount).contains($0) }
        require(
            componentsAreBounded
                && counts.total == counts.passed + counts.failed + counts.skipped,
            "QC.EVIDENCE.INVALID_TEST_COUNTS",
            &issues
        )

        guard let expectedTestGateID,
              let testGate = gates.first(where: { $0.id == expectedTestGateID }) else {
            require(false, "QC.EVIDENCE.MISSING_TEST_GATE", &issues)
            return
        }

        let expectedStatus: GateStatus
        if counts.total == 0 {
            expectedStatus = .blocked
        } else if counts.failed > 0 {
            expectedStatus = .fail
        } else {
            expectedStatus = .pass
        }
        require(
            testGate.status == expectedStatus,
            "QC.EVIDENCE.TEST_COUNT_GATE_MISMATCH",
            &issues
        )
    }

    private static func validateBounds(
        _ evidence: QualityEvidence,
        issues: inout [EvidenceVerificationIssue]
    ) {
        let collectionsAreBounded = evidence.commands.count <= 256
            && evidence.gates.count <= 256
            && evidence.artifacts.count <= 256
            && evidence.residualRisks.count <= 256
            && evidence.commands.allSatisfy { $0.commandLine.count <= 256 }
        let stringsAreBounded = [
            evidence.sourceRepository,
            evidence.engineVersion,
            evidence.toolchain.swiftVersion,
            evidence.toolchain.xcodeVersion
        ].allSatisfy(isBoundedNonEmptyString)
            && evidence.commands.allSatisfy {
                isBoundedNonEmptyString($0.id)
                    && $0.commandLine.allSatisfy(isBoundedNonEmptyString)
            }
            && evidence.gates.allSatisfy {
                isBoundedNonEmptyString($0.id)
                    && isBoundedNonEmptyString($0.message)
                    && $0.commandID.map(isBoundedNonEmptyString) != false
            }
            && evidence.artifacts.allSatisfy { isBoundedNonEmptyString($0.path) }
            && evidence.residualRisks.allSatisfy(isBoundedNonEmptyString)

        require(collectionsAreBounded, "QC.EVIDENCE.COLLECTION_LIMIT", &issues)
        require(stringsAreBounded, "QC.EVIDENCE.STRING_LIMIT", &issues)
    }

    private static func validateReviewRevision(
        _ reviewRevision: String?,
        sourceRevision: String,
        issues: inout [EvidenceVerificationIssue]
    ) {
        guard let reviewRevision else {
            return
        }
        validateRevision(reviewRevision, code: "QC.EVIDENCE.INVALID_REVIEW_REVISION", &issues)
        require(
            reviewRevision == sourceRevision,
            "QC.EVIDENCE.STALE_REVIEW_REVISION",
            &issues
        )
    }

    private static func validateArtifacts(
        _ artifacts: [EvidenceArtifact],
        expected: [String: String],
        issues: inout [EvidenceVerificationIssue]
    ) {
        let paths = artifacts.map(\.path)
        require(
            Set(paths).count == paths.count,
            "QC.EVIDENCE.DUPLICATE_ARTIFACT_PATH",
            &issues
        )

        for artifact in artifacts {
            require(
                isSafeRelativePath(artifact.path),
                "QC.EVIDENCE.INVALID_ARTIFACT_PATH",
                &issues
            )
            validateSHA256(artifact.sha256, code: "QC.EVIDENCE.INVALID_ARTIFACT_HASH", &issues)
        }

        require(
            artifacts.count == expected.count
                && expected.allSatisfy { path, sha256 in
                    artifacts.contains { $0.path == path && $0.sha256 == sha256 }
                },
            "QC.EVIDENCE.ARTIFACT_SET_MISMATCH",
            &issues
        )
    }

    private static func validateRevision(
        _ value: String,
        code: String,
        _ issues: inout [EvidenceVerificationIssue]
    ) {
        require(isLowercaseHex(value, count: 40), code, &issues)
    }

    private static func validateSHA256(
        _ value: String,
        code: String,
        _ issues: inout [EvidenceVerificationIssue]
    ) {
        require(isLowercaseHex(value, count: 64), code, &issues)
    }

    private static func isLowercaseHex(_ value: String, count: Int) -> Bool {
        let bytes = value.utf8
        guard bytes.count == count else {
            return false
        }
        return bytes.allSatisfy { byte in
            (0x30...0x39).contains(byte) || (0x61...0x66).contains(byte)
        }
    }

    private static func isSafeRelativePath(_ path: String) -> Bool {
        guard !path.isEmpty, !path.hasPrefix("/"), !path.hasPrefix("~") else {
            return false
        }
        return path.split(separator: "/", omittingEmptySubsequences: false).allSatisfy {
            !$0.isEmpty && $0 != "." && $0 != ".."
        }
    }

    private static func isBoundedNonEmptyString(_ value: String) -> Bool {
        value.utf8.count <= 4_096
            && value.rangeOfCharacter(from: .whitespacesAndNewlines.inverted) != nil
    }

    private static func require(
        _ condition: Bool,
        _ code: String,
        _ issues: inout [EvidenceVerificationIssue]
    ) {
        guard !condition else {
            return
        }
        issues.append(EvidenceVerificationIssue(code: code, message: message(for: code)))
    }

    private static func message(for code: String) -> String {
        "Evidence verification failed: \(code)."
    }
}
