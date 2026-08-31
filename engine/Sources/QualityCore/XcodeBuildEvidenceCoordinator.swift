import CryptoKit
import Foundation

/// Coordinator-owned identity observed outside the result bundle and evidence document.
///
/// A public execution boundary must authenticate both clean Git checkouts, the running engine code
/// identity, the selected toolchain, the exact profile bytes, and the user's build authorization
/// before constructing this package-internal context.
package struct XcodeBuildEvidenceObservedContext: Sendable {
    package let sourceRepository: String
    package let sourceRevision: String
    package let engineVersion: String
    package let engineRevision: String
    package let engineCodeDirectoryHash: String
    package let toolchain: EvidenceToolchain
    package let profileSnapshot: ProfileSnapshot
    package let executionAction: PermissionAction
    package let userAuthorizedActions: Set<PermissionAction>

    package init(
        sourceRepository: String,
        sourceRevision: String,
        engineVersion: String,
        engineRevision: String,
        engineCodeDirectoryHash: String,
        toolchain: EvidenceToolchain,
        profileSnapshot: ProfileSnapshot,
        executionAction: PermissionAction = .localBuildExecution,
        userAuthorizedActions: Set<PermissionAction>
    ) {
        self.sourceRepository = sourceRepository
        self.sourceRevision = sourceRevision
        self.engineVersion = engineVersion
        self.engineRevision = engineRevision
        self.engineCodeDirectoryHash = engineCodeDirectoryHash
        self.toolchain = toolchain
        self.profileSnapshot = profileSnapshot
        self.executionAction = executionAction
        self.userAuthorizedActions = userAuthorizedActions
    }
}

package struct XcodeBuildEvidenceReceipt: Sendable {
    package let observation: XcodeBuildSupervisionObservation
    package let evidence: QualityEvidence
    package let verification: EvidenceVerification
}

package enum XcodeBuildEvidenceCoordinationError: Error, Equatable {
    case invalidTrustedContext
    case invalidProfile
    case enginePinMismatch
    case undeclaredSelection
    case buildExecutionProhibited
    case missingBuildAuthorization
    case verificationFailed
}

/// Converts one authenticated supervisor observation into exact-input build evidence.
///
/// The coordinator accepts no caller-supplied command, gate, artifact, expectation, verdict, or
/// authorization label. Those values are derived from trusted context and the stable structured
/// result observation, preventing an evidence document from authorizing or verifying itself.
package enum XcodeBuildEvidenceCoordinator {
    package static let engineVersion = StaticEvidenceCoordinator.engineVersion
    private static let buildTimeoutSeconds = 15 * 60
    private static let buildResultsArtifactPath = "xcode/build-results.json"
    private static let buildLogArtifactPath = "xcode/build-log.json"

    package static func coordinate(
        observation: XcodeBuildSupervisionObservation,
        context: XcodeBuildEvidenceObservedContext
    ) throws -> XcodeBuildEvidenceReceipt {
        guard isValidObservation(observation) else {
            throw XcodeBuildEvidenceCoordinationError.invalidTrustedContext
        }
        try validate(context: context, selection: observation.selection)
        let profile = context.profileSnapshot.profile

        let buildAction = context.executionAction
        let artifacts = [
            EvidenceArtifact(
                path: buildResultsArtifactPath,
                sha256: observation.evidence.buildResultsSHA256
            ),
            EvidenceArtifact(
                path: buildLogArtifactPath,
                sha256: observation.evidence.buildLogSHA256
            )
        ]
        let command = EvidenceCommand(
            id: "xcode-build",
            commandSHA256: commandSHA256(
                observation: observation,
                context: context
            ),
            exitCode: 0,
            actions: [buildAction],
            authorization: .user
        )
        let gate = EvidenceGate(
            id: "QC.BUILD",
            status: .pass,
            message: "The supervised Xcode build completed with stable structured evidence.",
            commandID: command.id,
            actions: [buildAction]
        )
        let evidence = QualityEvidence(
            sourceRepository: context.sourceRepository,
            sourceRevision: context.sourceRevision,
            engineVersion: context.engineVersion,
            engineRevision: context.engineRevision,
            profileSchemaVersion: profile.schemaVersion,
            profileSHA256: context.profileSnapshot.sha256,
            toolchain: context.toolchain,
            permissions: profile.permissions,
            commands: [command],
            gates: [gate],
            artifacts: artifacts,
            claimedVerdict: .ready
        )
        let expected = EvidenceExpectation(
            sourceRepository: context.sourceRepository,
            sourceRevision: context.sourceRevision,
            engineVersion: context.engineVersion,
            engineRevision: context.engineRevision,
            profileSchemaVersion: profile.schemaVersion,
            profileSHA256: context.profileSnapshot.sha256,
            toolchain: context.toolchain,
            permissions: profile.permissions,
            commandsByID: [
                command.id: EvidenceCommandExpectation(
                    commandSHA256: command.commandSHA256,
                    exitCode: command.exitCode,
                    actions: [buildAction]
                )
            ],
            gatesByID: [
                gate.id: EvidenceGateExpectation(
                    commandID: gate.commandID,
                    actions: [buildAction],
                    status: gate.status,
                    message: gate.message
                )
            ],
            userAuthorizedActions: [buildAction],
            artifactSHA256ByPath: Dictionary(
                uniqueKeysWithValues: artifacts.map { ($0.path, $0.sha256) }
            )
        )
        let verification = EvidenceVerifier.verify(evidence, expected: expected)
        guard verification.issues.isEmpty, verification.verdict == .ready else {
            throw XcodeBuildEvidenceCoordinationError.verificationFailed
        }

        return XcodeBuildEvidenceReceipt(
            observation: observation,
            evidence: evidence,
            verification: verification
        )
    }

    package static func validate(
        context: XcodeBuildEvidenceObservedContext,
        selection: XcodeBuildSelection
    ) throws {
        guard isValidContext(context) else {
            throw XcodeBuildEvidenceCoordinationError.invalidTrustedContext
        }
        let profile = context.profileSnapshot.profile
        let profileIssues = ProfileValidator.validate(profile).filter {
            $0.code != "QC.PROFILE.XCODE_GRAPH_RESOLUTION_REQUIRED"
        }
        guard profile.schemaVersion == 2, profile.xcode != nil, profileIssues.isEmpty else {
            throw XcodeBuildEvidenceCoordinationError.invalidProfile
        }
        guard let engine = profile.engine,
              engine.version == context.engineVersion,
              engine.revision == context.engineRevision else {
            throw XcodeBuildEvidenceCoordinationError.enginePinMismatch
        }
        guard selectionIsDeclared(selection, in: profile) else {
            throw XcodeBuildEvidenceCoordinationError.undeclaredSelection
        }
        let buildAction = context.executionAction
        guard buildAction == .localBuildExecution || buildAction == .githubExecution else {
            throw XcodeBuildEvidenceCoordinationError.invalidTrustedContext
        }
        guard PermissionEvaluator.requirement(for: buildAction, policy: profile.permissions)
            != .prohibited else {
            throw XcodeBuildEvidenceCoordinationError.buildExecutionProhibited
        }
        guard context.userAuthorizedActions == [buildAction] else {
            throw XcodeBuildEvidenceCoordinationError.missingBuildAuthorization
        }
    }

    private static func commandSHA256(
        observation: XcodeBuildSupervisionObservation,
        context: XcodeBuildEvidenceObservedContext
    ) -> String {
        let selection = observation.selection
        let commandFields = [
            "aizenflow-quality/xcode-build-evidence-command/v1",
            context.sourceRepository,
            context.sourceRevision,
            context.engineVersion,
            context.engineRevision,
            context.engineCodeDirectoryHash,
            String(context.profileSnapshot.profile.schemaVersion),
            context.profileSnapshot.sha256,
            context.toolchain.swiftVersion,
            context.toolchain.xcodeVersion,
            selection.scheme,
            selection.configuration,
            selection.destination,
            context.executionAction.rawValue,
            String(buildTimeoutSeconds)
        ]
        var canonicalInput = Data()
        for field in commandFields {
            var byteCount = UInt64(field.utf8.count).bigEndian
            withUnsafeBytes(of: &byteCount) { canonicalInput.append(contentsOf: $0) }
            canonicalInput.append(contentsOf: field.utf8)
        }
        return SHA256.hash(data: canonicalInput).map {
            String(format: "%02x", $0)
        }.joined()
    }

    private static func isValidContext(
        _ context: XcodeBuildEvidenceObservedContext
    ) -> Bool {
        EvidenceVerifier.isBoundedNonEmptyString(context.sourceRepository)
            && isLowercaseHex(context.sourceRevision, count: 40)
            && context.engineVersion == engineVersion
            && isLowercaseHex(context.engineRevision, count: 40)
            && isLowercaseHex(context.engineCodeDirectoryHash, count: 40)
            && EvidenceVerifier.isBoundedNonEmptyString(context.toolchain.swiftVersion)
            && EvidenceVerifier.isBoundedNonEmptyString(context.toolchain.xcodeVersion)
    }

    private static func isValidObservation(
        _ observation: XcodeBuildSupervisionObservation
    ) -> Bool {
        isLowercaseHex(observation.evidence.buildResultsSHA256, count: 64)
            && isLowercaseHex(observation.evidence.buildLogSHA256, count: 64)
            && EvidenceVerifier.isBoundedNonEmptyString(observation.selection.scheme)
            && EvidenceVerifier.isBoundedNonEmptyString(observation.selection.configuration)
            && EvidenceVerifier.isBoundedNonEmptyString(observation.selection.destination)
    }

    private static func selectionIsDeclared(
        _ selection: XcodeBuildSelection,
        in profile: ProjectProfile
    ) -> Bool {
        profile.xcode?.schemes.contains(where: { scheme in
            scheme.name == selection.scheme
                && scheme.configurations.contains(selection.configuration)
                && scheme.destinations.contains(selection.destination)
        }) == true
    }

    private static func isLowercaseHex(_ value: String, count: Int) -> Bool {
        let bytes = value.utf8
        return bytes.count == count && bytes.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
    }
}

/// Versioned public result for one `build-evidence` execution.
///
/// Only a fully coordinated PASS carries evidence. Preflight, build, mutation, or verification
/// failures carry a terminal report and nil evidence so consumers cannot mistake partial work for
/// exact-SHA proof.
public struct XcodeBuildEvidenceExecutionResult: Encodable, Sendable {
    public static let currentSchemaVersion = 1
    public let schemaVersion: Int
    public let command: String
    public let status: QualityStatus
    public let report: QualityReport
    public let evidence: QualityEvidence?
    public let verification: EvidenceVerification?

    package init(report: QualityReport) {
        schemaVersion = Self.currentSchemaVersion
        command = "build-evidence"
        if report.command != "build" || report.status == .pass {
            self.report = QualityReport(
                command: "build",
                checks: [
                    QualityCheck(
                        id: "QC.BUILD_EVIDENCE.UNVERIFIED_PASS",
                        status: .blocked,
                        message: "An unverified build PASS cannot be emitted as build evidence."
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

    package init(receipt: XcodeBuildEvidenceReceipt) {
        schemaVersion = Self.currentSchemaVersion
        command = "build-evidence"
        status = .pass
        report = QualityReport(
            command: "build",
            checks: [
                QualityCheck(
                    id: "QC.BUILD",
                    status: .pass,
                    message: "The supervised Xcode build produced verified exact-input evidence."
                )
            ]
        )
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

package typealias XcodeBuildSupervisorRunner = (
    _ profile: ProjectProfile,
    _ selection: XcodeBuildSelection
) throws -> XcodeBuildSupervisionObservation

package typealias XcodeBuildBoundaryObserver = () -> XcodeBuildEvidenceObservedContext?

package enum XcodeBuildEvidenceExecution {
    package static func selection(
        scheme: String,
        configuration: String,
        destination: String
    ) -> XcodeBuildSelection {
        XcodeBuildSelection(
            scheme: scheme,
            configuration: configuration,
            destination: destination
        )
    }

    package static func execute(
        initialContext: XcodeBuildEvidenceObservedContext,
        selection: XcodeBuildSelection,
        runBuild: XcodeBuildSupervisorRunner,
        observeFinalContext: XcodeBuildBoundaryObserver
    ) -> XcodeBuildEvidenceExecutionResult {
        do {
            try XcodeBuildEvidenceCoordinator.validate(
                context: initialContext,
                selection: selection
            )
        } catch {
            return blocked(
                "QC.BUILD_EVIDENCE.PREFLIGHT_UNTRUSTED",
                "Build evidence preflight identity, profile, selection, or authorization is invalid."
            )
        }

        let observation: XcodeBuildSupervisionObservation
        do {
            observation = try runBuild(initialContext.profileSnapshot.profile, selection)
        } catch let error as XcodeBuildEvidenceSupervisionError {
            if case .verification(.buildProcessFailed(_)) = error {
                return failed(
                    "QC.BUILD_EVIDENCE.BUILD_FAILED",
                    "The supervised Xcode build failed."
                )
            }
            if case .verification(.unsuccessfulBuildResult) = error {
                return failed(
                    "QC.BUILD_EVIDENCE.BUILD_FAILED",
                    "The supervised Xcode build result was unsuccessful."
                )
            }
            return blocked(
                "QC.BUILD_EVIDENCE.SUPERVISION_FAILED",
                "The Xcode build could not produce trustworthy structured evidence."
            )
        } catch {
            return blocked(
                "QC.BUILD_EVIDENCE.SUPERVISION_FAILED",
                "The Xcode build supervisor failed at its execution boundary."
            )
        }

        guard let finalContext = observeFinalContext(),
              identitiesMatch(initialContext, finalContext) else {
            return blocked(
                "QC.BUILD_EVIDENCE.INPUT_CHANGED",
                "Source, engine, profile, toolchain, or execution authority changed during the build."
            )
        }

        do {
            return XcodeBuildEvidenceExecutionResult(
                receipt: try XcodeBuildEvidenceCoordinator.coordinate(
                    observation: observation,
                    context: initialContext
                )
            )
        } catch {
            return blocked(
                "QC.BUILD_EVIDENCE.VERIFICATION_FAILED",
                "Observed build facts could not be converted into verified exact-input evidence."
            )
        }
    }

    private static func identitiesMatch(
        _ lhs: XcodeBuildEvidenceObservedContext,
        _ rhs: XcodeBuildEvidenceObservedContext
    ) -> Bool {
        lhs.sourceRepository == rhs.sourceRepository
            && lhs.sourceRevision == rhs.sourceRevision
            && lhs.engineVersion == rhs.engineVersion
            && lhs.engineRevision == rhs.engineRevision
            && lhs.engineCodeDirectoryHash == rhs.engineCodeDirectoryHash
            && lhs.toolchain == rhs.toolchain
            && lhs.profileSnapshot.sha256 == rhs.profileSnapshot.sha256
            && lhs.executionAction == rhs.executionAction
            && lhs.userAuthorizedActions == rhs.userAuthorizedActions
    }

    private static func failed(
        _ id: String,
        _ message: String
    ) -> XcodeBuildEvidenceExecutionResult {
        XcodeBuildEvidenceExecutionResult(
            report: QualityReport(
                command: "build",
                checks: [QualityCheck(id: id, status: .fail, message: message)]
            )
        )
    }

    private static func blocked(
        _ id: String,
        _ message: String
    ) -> XcodeBuildEvidenceExecutionResult {
        XcodeBuildEvidenceExecutionResult(
            report: QualityReport(
                command: "build",
                checks: [QualityCheck(id: id, status: .blocked, message: message)]
            )
        )
    }
}
