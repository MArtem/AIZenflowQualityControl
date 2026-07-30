import Foundation
import Testing
@testable import QualityCore

@Suite("Permission and evidence contracts")
struct EvidenceContractTests {
    private let sourceRevision = String(repeating: "a", count: 40)
    private let engineRevision = String(repeating: "b", count: 40)
    private let profileHash = String(repeating: "c", count: 64)
    private let artifactHash = String(repeating: "d", count: 64)
    private let toolchain = EvidenceToolchain(
        swiftVersion: "Apple Swift 6.1.2",
        xcodeVersion: "Xcode 16.4 (16F6)"
    )

    private var policy: PermissionPolicy {
        PermissionPolicy(
            testCreation: .allow,
            testModification: .deny,
            localTestExecution: .ask,
            githubExecution: .manual,
            uiTests: .allow,
            simulatorOrDevice: .deny,
            performanceOrInstruments: .ask
        )
    }

    @Test(
        "Each permission remains independently enforceable",
        arguments: [
            (PermissionAction.testCreation, PermissionRequirement.authorizedByProfile),
            (.testModification, .prohibited),
            (.localTestExecution, .userAuthorizationRequired),
            (.githubExecution, .userAuthorizationRequired),
            (.uiTests, .authorizedByProfile),
            (.simulatorOrDevice, .prohibited),
            (.performanceOrInstruments, .userAuthorizationRequired)
        ]
    )
    func independentPermission(
        action: PermissionAction,
        expected: PermissionRequirement
    ) {
        #expect(PermissionEvaluator.requirement(for: action, policy: policy) == expected)
    }

    @Test("Exact trusted context verifies as READY")
    func exactEvidenceIsReady() {
        let result = EvidenceVerifier.verify(validEvidence(), expected: expectation())

        #expect(result.verdict == .ready)
        #expect(result.issues.isEmpty)
    }

    @Test(
        "Gate aggregation never turns a non-run state into READY",
        arguments: [
            (GateStatus.pass, AdvisoryVerdict.ready),
            (.fail, .notReady),
            (.blocked, .blocked),
            (.notApplicable, .blocked),
            (.notRunByUserDecision, .needsOwnerDecision),
            (.skipped, .blocked)
        ]
    )
    func gateAggregation(status: GateStatus, expected: AdvisoryVerdict) {
        let commandID: String? = status == .pass || status == .fail ? "static" : nil
        let gate = EvidenceGate(
            id: "QC.TEST.GATE",
            status: status,
            message: "Concrete gate state.",
            commandID: commandID
        )

        #expect(EvidenceVerifier.aggregate([gate]) == expected)
    }

    @Test("Stale source evidence is BYPASSED")
    func staleSourceIsBypassed() {
        let staleExpectation = expectation(sourceRevision: String(repeating: "e", count: 40))

        let result = EvidenceVerifier.verify(validEvidence(), expected: staleExpectation)

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.STALE_SOURCE_REVISION"))
    }

    @Test("A forged artifact hash is BYPASSED")
    func forgedArtifactIsBypassed() {
        let forgedExpectation = expectation(
            artifactHash: String(repeating: "e", count: 64)
        )

        let result = EvidenceVerifier.verify(validEvidence(), expected: forgedExpectation)

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.ARTIFACT_SET_MISMATCH"))
    }

    @Test("A stale review cannot prove the current source")
    func staleReviewIsBypassed() {
        let evidence = validEvidence(reviewRevision: String(repeating: "e", count: 40))

        let result = EvidenceVerifier.verify(evidence, expected: expectation())

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.STALE_REVIEW_REVISION"))
    }

    @Test("A weakened permission snapshot is BYPASSED")
    func weakenedPermissionSnapshotIsBypassed() {
        let weakenedPolicy = PermissionPolicy(
            testCreation: .allow,
            testModification: .allow,
            localTestExecution: .allow,
            githubExecution: .manual,
            uiTests: .allow,
            simulatorOrDevice: .allow,
            performanceOrInstruments: .allow
        )
        let evidence = validEvidence(permissions: weakenedPolicy)

        let result = EvidenceVerifier.verify(evidence, expected: expectation())

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.PERMISSION_SNAPSHOT_MISMATCH"))
    }

    @Test("A prohibited action cannot appear as an executed command")
    func prohibitedCommandIsBypassed() {
        let command = EvidenceCommand(
            id: "tests",
            commandLine: ["swift", "test"],
            exitCode: 0,
            action: .testModification,
            authorization: .user
        )
        let evidence = validEvidence(
            commands: [command],
            gates: [
                EvidenceGate(
                    id: "QC.TESTS",
                    status: .pass,
                    message: "Tests passed.",
                    commandID: "tests",
                    action: .testModification
                )
            ],
            artifacts: [],
            claimedVerdict: .ready
        )

        let result = EvidenceVerifier.verify(
            evidence,
            expected: expectation(
                commands: ["tests": ["swift", "test"]],
                gateIDs: ["QC.TESTS"],
                artifacts: [:]
            )
        )

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.PROHIBITED_COMMAND_EXECUTED"))
    }

    @Test("An ask action requires explicit user authorization")
    func missingUserAuthorizationIsBypassed() {
        let command = EvidenceCommand(
            id: "tests",
            commandLine: ["swift", "test"],
            exitCode: 0,
            action: .localTestExecution,
            authorization: .profile
        )
        let evidence = validEvidence(
            commands: [command],
            gates: [
                EvidenceGate(
                    id: "QC.TESTS",
                    status: .pass,
                    message: "Tests passed.",
                    commandID: "tests",
                    action: .localTestExecution
                )
            ],
            artifacts: [],
            claimedVerdict: .ready
        )

        let result = EvidenceVerifier.verify(
            evidence,
            expected: expectation(
                commands: ["tests": ["swift", "test"]],
                gateIDs: ["QC.TESTS"],
                artifacts: [:]
            )
        )

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.MISSING_USER_AUTHORIZATION"))
    }

    @Test("A trusted user authorization permits an ask action")
    func trustedUserAuthorizationIsAccepted() {
        let command = EvidenceCommand(
            id: "tests",
            commandLine: ["swift", "test"],
            exitCode: 0,
            action: .localTestExecution,
            authorization: .user
        )
        let evidence = validEvidence(
            commands: [command],
            gates: [
                EvidenceGate(
                    id: "QC.TESTS",
                    status: .pass,
                    message: "Tests passed.",
                    commandID: "tests",
                    action: .localTestExecution
                )
            ],
            artifacts: [],
            claimedVerdict: .ready
        )

        let result = EvidenceVerifier.verify(
            evidence,
            expected: expectation(
                commands: ["tests": ["swift", "test"]],
                gateIDs: ["QC.TESTS"],
                userAuthorizedActions: [.localTestExecution],
                artifacts: [:]
            )
        )

        #expect(result.verdict == .ready)
        #expect(result.issues.isEmpty)
    }

    @Test("A self-asserted user authorization is not trusted")
    func selfAssertedUserAuthorizationIsBypassed() {
        let command = EvidenceCommand(
            id: "tests",
            commandLine: ["swift", "test"],
            exitCode: 0,
            action: .localTestExecution,
            authorization: .user
        )
        let evidence = validEvidence(
            commands: [command],
            gates: [
                EvidenceGate(
                    id: "QC.TESTS",
                    status: .pass,
                    message: "Tests passed.",
                    commandID: "tests",
                    action: .localTestExecution
                )
            ],
            artifacts: [],
            claimedVerdict: .ready
        )

        let result = EvidenceVerifier.verify(
            evidence,
            expected: expectation(
                commands: ["tests": ["swift", "test"]],
                gateIDs: ["QC.TESTS"],
                artifacts: [:]
            )
        )

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.MISSING_USER_AUTHORIZATION"))
    }

    @Test("A forged command line is BYPASSED")
    func forgedCommandIsBypassed() {
        let result = EvidenceVerifier.verify(
            validEvidence(),
            expected: expectation(commands: ["static": ["true"]])
        )

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.COMMAND_SET_MISMATCH"))
    }

    @Test("Missing expected gate evidence is BYPASSED")
    func missingGateIsBypassed() {
        let result = EvidenceVerifier.verify(
            validEvidence(),
            expected: expectation(gateIDs: ["QC.STATIC", "QC.TESTS"])
        )

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.GATE_SET_MISMATCH"))
    }

    @Test("Self-asserted test counts are BYPASSED")
    func forgedTestCountsAreBypassed() {
        let evidence = QualityEvidence(
            sourceRepository: "MArtem/AIZenflowQualityControl",
            sourceRevision: sourceRevision,
            engineVersion: "0.1.0",
            engineRevision: engineRevision,
            profileSchemaVersion: 1,
            profileSHA256: profileHash,
            toolchain: toolchain,
            permissions: policy,
            commands: [
                EvidenceCommand(
                    id: "static",
                    commandLine: ["swift", "run", "quality", "static"],
                    exitCode: 0
                )
            ],
            gates: [
                EvidenceGate(
                    id: "QC.STATIC",
                    status: .pass,
                    message: "Static checks passed.",
                    commandID: "static"
                )
            ],
            testCounts: EvidenceTestCounts(total: 1, passed: 1, failed: 0, skipped: 0),
            artifacts: [
                EvidenceArtifact(path: "reports/static.json", sha256: artifactHash)
            ],
            residualRisks: ["No Xcode build was run."],
            claimedVerdict: .ready
        )

        let result = EvidenceVerifier.verify(evidence, expected: expectation())

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.TEST_COUNTS_MISMATCH"))
    }

    @Test("PASS evidence requires a zero command exit code")
    func passWithNonzeroExitIsBypassed() {
        let evidence = validEvidence(
            commands: [
                EvidenceCommand(
                    id: "static",
                    commandLine: ["swift", "run", "quality", "static"],
                    exitCode: 1
                )
            ]
        )

        let result = EvidenceVerifier.verify(evidence, expected: expectation())

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.PASS_EXIT_CODE_MISMATCH"))
    }

    @Test("A skipped gate cannot carry a forged READY verdict")
    func skippedReadyClaimIsBypassed() {
        let evidence = validEvidence(
            gates: [
                EvidenceGate(
                    id: "QC.TESTS",
                    status: .skipped,
                    message: "Job did not run."
                )
            ],
            claimedVerdict: .ready
        )

        let result = EvidenceVerifier.verify(
            evidence,
            expected: expectation(gateIDs: ["QC.TESTS"])
        )

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.CLAIMED_VERDICT_MISMATCH"))
    }

    @Test("Evidence has a stable Codable representation")
    func evidenceRoundTrip() throws {
        let evidence = validEvidence()
        let encoded = try JSONEncoder().encode(evidence)
        let decoded = try JSONDecoder().decode(QualityEvidence.self, from: encoded)

        #expect(decoded.schemaVersion == 1)
        #expect(decoded.sourceRevision == sourceRevision)
        #expect(decoded.gates.map(\.status) == [.pass])
        #expect(decoded.claimedVerdict == .ready)
    }

    private func validEvidence(
        permissions: PermissionPolicy? = nil,
        commands: [EvidenceCommand]? = nil,
        gates: [EvidenceGate]? = nil,
        reviewRevision: String? = nil,
        artifacts: [EvidenceArtifact]? = nil,
        claimedVerdict: AdvisoryVerdict = .ready
    ) -> QualityEvidence {
        QualityEvidence(
            sourceRepository: "MArtem/AIZenflowQualityControl",
            sourceRevision: sourceRevision,
            engineVersion: "0.1.0",
            engineRevision: engineRevision,
            profileSchemaVersion: 1,
            profileSHA256: profileHash,
            toolchain: toolchain,
            permissions: permissions ?? policy,
            commands: commands ?? [
                EvidenceCommand(
                    id: "static",
                    commandLine: ["swift", "run", "quality", "static"],
                    exitCode: 0
                )
            ],
            gates: gates ?? [
                EvidenceGate(
                    id: "QC.STATIC",
                    status: .pass,
                    message: "Static checks passed.",
                    commandID: "static"
                )
            ],
            testCounts: nil,
            reviewRevision: reviewRevision,
            artifacts: artifacts ?? [
                EvidenceArtifact(path: "reports/static.json", sha256: artifactHash)
            ],
            residualRisks: ["No Xcode build was run."],
            claimedVerdict: claimedVerdict
        )
    }

    private func expectation(
        sourceRevision: String? = nil,
        artifactHash: String? = nil,
        commands: [String: [String]]? = nil,
        gateIDs: Set<String>? = nil,
        userAuthorizedActions: Set<PermissionAction> = [],
        artifacts: [String: String]? = nil
    ) -> EvidenceExpectation {
        EvidenceExpectation(
            sourceRepository: "MArtem/AIZenflowQualityControl",
            sourceRevision: sourceRevision ?? self.sourceRevision,
            engineVersion: "0.1.0",
            engineRevision: engineRevision,
            profileSchemaVersion: 1,
            profileSHA256: profileHash,
            toolchain: toolchain,
            permissions: policy,
            commandLinesByID: commands ?? [
                "static": ["swift", "run", "quality", "static"]
            ],
            gateIDs: gateIDs ?? ["QC.STATIC"],
            userAuthorizedActions: userAuthorizedActions,
            artifactSHA256ByPath: artifacts ?? [
                "reports/static.json": artifactHash ?? self.artifactHash
            ],
            residualRisks: ["No Xcode build was run."]
        )
    }
}
