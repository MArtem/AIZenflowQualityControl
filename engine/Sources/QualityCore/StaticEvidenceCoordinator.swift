import CryptoKit
import Foundation

/// Coordinator-owned metadata observed outside untrusted evidence documents.
///
/// Stage 9C2B deliberately keeps this package-internal. A later execution boundary is responsible
/// for collecting these facts from the source checkout and selected toolchain.
package struct StaticEvidenceObservedContext: Sendable {
    package let sourceRepository: String
    package let sourceRevision: String
    package let engineRevision: String
    package let toolchain: EvidenceToolchain
    package let profileSnapshot: ProfileSnapshot

    package init(
        sourceRepository: String,
        sourceRevision: String,
        engineRevision: String,
        toolchain: EvidenceToolchain,
        profileSnapshot: ProfileSnapshot
    ) {
        self.sourceRepository = sourceRepository
        self.sourceRevision = sourceRevision
        self.engineRevision = engineRevision
        self.toolchain = toolchain
        self.profileSnapshot = profileSnapshot
    }
}

package struct StaticEvidenceReceipt: Sendable {
    package let report: QualityReport
    package let evidence: QualityEvidence
    package let verification: EvidenceVerification
}

package enum StaticEvidenceCoordinationError: Error {
    case invalidTrustedContext
    case invalidProfile
    case missingProfileDigest
    case missingPolicyDigest
    case profileDigestMismatch
    case verificationFailed
}

/// Converts an already authenticated static-worker observation into in-memory evidence.
///
/// This type neither reads documents nor launches processes. It accepts no caller-supplied command,
/// gate, expectation, verdict, authorization, or evidence JSON, so those values cannot authorize
/// themselves. Stage 9D will own trusted observation and public integration.
package enum StaticEvidenceCoordinator {
    package static let engineVersion = "0.1.0-dev"

    package static func coordinate(
        observation: ValidatedStaticWorkerObservation,
        context: StaticEvidenceObservedContext
    ) throws -> StaticEvidenceReceipt {
        guard isValidContext(context) else {
            throw StaticEvidenceCoordinationError.invalidTrustedContext
        }
        guard ProfileValidator.validate(context.profileSnapshot.profile).isEmpty else {
            throw StaticEvidenceCoordinationError.invalidProfile
        }
        guard let profileSHA256 = observation.profileSHA256 else {
            throw StaticEvidenceCoordinationError.missingProfileDigest
        }
        guard let policySHA256 = observation.policySHA256 else {
            throw StaticEvidenceCoordinationError.missingPolicyDigest
        }
        guard profileSHA256 == context.profileSnapshot.sha256 else {
            throw StaticEvidenceCoordinationError.profileDigestMismatch
        }

        let command = EvidenceCommand(
            id: "static",
            commandSHA256: commandSHA256(
                sourceRepository: context.sourceRepository,
                sourceRevision: context.sourceRevision,
                engineVersion: engineVersion,
                engineRevision: context.engineRevision,
                profileSHA256: profileSHA256,
                policySHA256: policySHA256
            ),
            exitCode: exitCode(for: observation.report.status)
        )
        let gate = EvidenceGate(
            id: "QC.STATIC",
            status: gateStatus(for: observation.report.status),
            message: gateMessage(for: observation.report.status),
            commandID: command.id
        )
        let claimedVerdict = verdict(for: observation.report.status)
        let evidence = QualityEvidence(
            sourceRepository: context.sourceRepository,
            sourceRevision: context.sourceRevision,
            engineVersion: engineVersion,
            engineRevision: context.engineRevision,
            profileSchemaVersion: context.profileSnapshot.profile.schemaVersion,
            profileSHA256: profileSHA256,
            toolchain: context.toolchain,
            permissions: context.profileSnapshot.profile.permissions,
            commands: [command],
            gates: [gate],
            claimedVerdict: claimedVerdict
        )
        let expected = EvidenceExpectation(
            sourceRepository: context.sourceRepository,
            sourceRevision: context.sourceRevision,
            engineVersion: engineVersion,
            engineRevision: context.engineRevision,
            profileSchemaVersion: context.profileSnapshot.profile.schemaVersion,
            profileSHA256: profileSHA256,
            toolchain: context.toolchain,
            permissions: context.profileSnapshot.profile.permissions,
            commandsByID: [
                command.id: EvidenceCommandExpectation(
                    commandSHA256: command.commandSHA256,
                    exitCode: command.exitCode
                )
            ],
            gatesByID: [
                gate.id: EvidenceGateExpectation(
                    commandID: gate.commandID,
                    status: gate.status,
                    message: gate.message
                )
            ]
        )
        let verification = EvidenceVerifier.verify(evidence, expected: expected)
        guard verification.issues.isEmpty, verification.verdict == claimedVerdict else {
            throw StaticEvidenceCoordinationError.verificationFailed
        }

        return StaticEvidenceReceipt(
            report: observation.report,
            evidence: evidence,
            verification: verification
        )
    }

    private static func commandSHA256(
        sourceRepository: String,
        sourceRevision: String,
        engineVersion: String,
        engineRevision: String,
        profileSHA256: String,
        policySHA256: String
    ) -> String {
        let canonicalInput = [
            "aizenflow-quality/static-evidence-command/v1",
            sourceRepository,
            sourceRevision,
            engineVersion,
            engineRevision,
            profileSHA256,
            policySHA256
        ].joined(separator: "\n")
        return SHA256.hash(data: Data(canonicalInput.utf8)).map {
            String(format: "%02x", $0)
        }.joined()
    }

    private static func isValidContext(_ context: StaticEvidenceObservedContext) -> Bool {
        isBoundedNonEmptyString(context.sourceRepository)
            && isLowercaseHex(context.sourceRevision, count: 40)
            && isLowercaseHex(context.engineRevision, count: 40)
            && isBoundedNonEmptyString(context.toolchain.swiftVersion)
            && isBoundedNonEmptyString(context.toolchain.xcodeVersion)
    }

    private static func isBoundedNonEmptyString(_ value: String) -> Bool {
        var scalarCount = 0
        var containsNonWhitespace = false
        for scalar in value.unicodeScalars.prefix(1_025) {
            scalarCount += 1
            if scalar != " " && scalar != "\t" && scalar != "\n" && scalar != "\r" {
                containsNonWhitespace = true
            }
        }
        return scalarCount <= 1_024 && containsNonWhitespace
    }

    private static func isLowercaseHex(_ value: String, count: Int) -> Bool {
        let bytes = value.utf8
        return bytes.count == count && bytes.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
    }

    private static func exitCode(for status: QualityStatus) -> Int {
        switch status {
        case .pass:
            return 0
        case .fail:
            return 1
        case .blocked:
            return 2
        }
    }

    private static func gateStatus(for status: QualityStatus) -> GateStatus {
        switch status {
        case .pass:
            return .pass
        case .fail:
            return .fail
        case .blocked:
            return .blocked
        }
    }

    private static func gateMessage(for status: QualityStatus) -> String {
        switch status {
        case .pass:
            return "The bounded static worker completed with PASS."
        case .fail:
            return "The bounded static worker completed with FAIL."
        case .blocked:
            return "The bounded static worker completed with BLOCKED."
        }
    }

    private static func verdict(for status: QualityStatus) -> AdvisoryVerdict {
        switch status {
        case .pass:
            return .ready
        case .fail:
            return .notReady
        case .blocked:
            return .blocked
        }
    }
}
