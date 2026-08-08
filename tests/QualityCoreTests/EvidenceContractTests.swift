import Foundation
import Testing
@testable import QualityCore

@Suite("Permission and evidence contracts")
struct EvidenceContractTests {
    private let sourceRevision = String(repeating: "a", count: 40)
    private let engineRevision = String(repeating: "b", count: 40)
    private let profileHash = String(repeating: "c", count: 64)
    private let artifactHash = String(repeating: "d", count: 64)
    private let staticCommandHash = String(repeating: "e", count: 64)
    private let testsCommandHash = String(repeating: "f", count: 64)
    private let uiCommandHash = String(repeating: "0", count: 64)
    private let auxiliaryCommandHash = String(repeating: "1", count: 64)
    private let forgedCommandHash = String(repeating: "2", count: 64)
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

    @Test("Unsupported profile schema versions are BYPASSED")
    func unsupportedProfileSchemaVersionIsBypassed() {
        let result = EvidenceVerifier.verify(
            validEvidence(profileSchemaVersion: 2),
            expected: expectation(profileSchemaVersion: 2)
        )

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.UNSUPPORTED_PROFILE_SCHEMA"))
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
            commandSHA256: testsCommandHash,
            exitCode: 0,
            actions: [.testModification],
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
                    actions: [.testModification]
                )
            ],
            artifacts: [],
            claimedVerdict: .ready
        )

        let result = EvidenceVerifier.verify(
            evidence,
            expected: expectation(
                commands: [
                    "tests": EvidenceCommandExpectation(
                        commandSHA256: testsCommandHash,
                        exitCode: 0,
                        actions: [.testModification]
                    )
                ],
                gates: [
                    "QC.TESTS": EvidenceGateExpectation(
                        commandID: "tests",
                        actions: [.testModification],
                        status: .pass,
                        message: "Tests passed."
                    )
                ],
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
            commandSHA256: testsCommandHash,
            exitCode: 0,
            actions: [.localTestExecution],
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
                    actions: [.localTestExecution]
                )
            ],
            artifacts: [],
            claimedVerdict: .ready
        )

        let result = EvidenceVerifier.verify(
            evidence,
            expected: expectation(
                commands: [
                    "tests": EvidenceCommandExpectation(
                        commandSHA256: testsCommandHash,
                        exitCode: 0,
                        actions: [.localTestExecution]
                    )
                ],
                gates: [
                    "QC.TESTS": EvidenceGateExpectation(
                        commandID: "tests",
                        actions: [.localTestExecution],
                        status: .pass,
                        message: "Tests passed."
                    )
                ],
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
            commandSHA256: testsCommandHash,
            exitCode: 0,
            actions: [.localTestExecution],
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
                    actions: [.localTestExecution]
                )
            ],
            artifacts: [],
            claimedVerdict: .ready
        )

        let result = EvidenceVerifier.verify(
            evidence,
            expected: expectation(
                commands: [
                    "tests": EvidenceCommandExpectation(
                        commandSHA256: testsCommandHash,
                        exitCode: 0,
                        actions: [.localTestExecution]
                    )
                ],
                gates: [
                    "QC.TESTS": EvidenceGateExpectation(
                        commandID: "tests",
                        actions: [.localTestExecution],
                        status: .pass,
                        message: "Tests passed."
                    )
                ],
                userAuthorizedActions: [.localTestExecution],
                artifacts: [:]
            )
        )

        #expect(result.verdict == .ready)
        #expect(result.issues.isEmpty)
    }

    @Test("Every action in a multi-permission command is enforced")
    func prohibitedMemberOfMultiActionCommandIsBypassed() {
        let actions: [PermissionAction] = [
            .uiTests,
            .localTestExecution,
            .simulatorOrDevice
        ]
        let evidence = validEvidence(
            commands: [
                EvidenceCommand(
                    id: "ui-tests",
                    commandSHA256: uiCommandHash,
                    exitCode: 0,
                    actions: actions,
                    authorization: .user
                )
            ],
            gates: [
                EvidenceGate(
                    id: "QC.UI_TESTS",
                    status: .pass,
                    message: "UI tests passed.",
                    commandID: "ui-tests",
                    actions: actions
                )
            ],
            artifacts: []
        )
        let expected = expectation(
            commands: [
                "ui-tests": EvidenceCommandExpectation(
                    commandSHA256: uiCommandHash,
                    exitCode: 0,
                    actions: Set(actions)
                )
            ],
            gates: [
                "QC.UI_TESTS": EvidenceGateExpectation(
                    commandID: "ui-tests",
                    actions: Set(actions),
                    status: .pass,
                    message: "UI tests passed."
                )
            ],
            userAuthorizedActions: [.localTestExecution],
            artifacts: [:]
        )

        let result = EvidenceVerifier.verify(evidence, expected: expected)

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.PROHIBITED_COMMAND_EXECUTED"))
    }

    @Test("A self-asserted user authorization is not trusted")
    func selfAssertedUserAuthorizationIsBypassed() {
        let command = EvidenceCommand(
            id: "tests",
            commandSHA256: testsCommandHash,
            exitCode: 0,
            actions: [.localTestExecution],
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
                    actions: [.localTestExecution]
                )
            ],
            artifacts: [],
            claimedVerdict: .ready
        )

        let result = EvidenceVerifier.verify(
            evidence,
            expected: expectation(
                commands: [
                    "tests": EvidenceCommandExpectation(
                        commandSHA256: testsCommandHash,
                        exitCode: 0,
                        actions: [.localTestExecution]
                    )
                ],
                gates: [
                    "QC.TESTS": EvidenceGateExpectation(
                        commandID: "tests",
                        actions: [.localTestExecution],
                        status: .pass,
                        message: "Tests passed."
                    )
                ],
                artifacts: [:]
            )
        )

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.MISSING_USER_AUTHORIZATION"))
    }

    @Test("A forged command identity is BYPASSED")
    func forgedCommandIdentityIsBypassed() {
        let result = EvidenceVerifier.verify(
            validEvidence(),
            expected: expectation(
                commands: [
                    "static": EvidenceCommandExpectation(
                        commandSHA256: forgedCommandHash,
                        exitCode: 0
                    )
                ]
            )
        )

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.COMMAND_SET_MISMATCH"))
    }

    @Test("A forged command outcome is BYPASSED")
    func forgedCommandExitCodeIsBypassed() {
        let result = EvidenceVerifier.verify(
            validEvidence(),
            expected: expectation(
                commands: [
                    "static": EvidenceCommandExpectation(
                        commandSHA256: staticCommandHash,
                        exitCode: 1
                    )
                ]
            )
        )

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.COMMAND_SET_MISMATCH"))
    }

    @Test("A permission action cannot be omitted from trusted command context")
    func omittedCommandActionIsBypassed() {
        let evidence = validEvidence(
            commands: [
                EvidenceCommand(
                    id: "tests",
                    commandSHA256: testsCommandHash,
                    exitCode: 0
                )
            ],
            gates: [
                EvidenceGate(
                    id: "QC.TESTS",
                    status: .pass,
                    message: "Tests passed.",
                    commandID: "tests"
                )
            ],
            artifacts: []
        )
        let expected = expectation(
            commands: [
                "tests": EvidenceCommandExpectation(
                    commandSHA256: testsCommandHash,
                    exitCode: 0,
                    actions: [.localTestExecution]
                )
            ],
            gates: [
                "QC.TESTS": EvidenceGateExpectation(
                    commandID: "tests",
                    actions: [.localTestExecution],
                    status: .pass,
                    message: "Tests passed."
                )
            ],
            userAuthorizedActions: [.localTestExecution],
            artifacts: [:]
        )

        let result = EvidenceVerifier.verify(evidence, expected: expected)

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.COMMAND_SET_MISMATCH"))
    }

    @Test("Each gate remains bound to its trusted command")
    func gateCannotBorrowAnotherCommandOutcome() {
        let evidence = validEvidence(
            commands: [
                EvidenceCommand(
                    id: "static",
                    commandSHA256: staticCommandHash,
                    exitCode: 0
                ),
                EvidenceCommand(
                    id: "tests",
                    commandSHA256: testsCommandHash,
                    exitCode: 0,
                    actions: [.localTestExecution],
                    authorization: .user
                )
            ],
            gates: [
                EvidenceGate(
                    id: "QC.STATIC",
                    status: .pass,
                    message: "Static passed.",
                    commandID: "static"
                ),
                EvidenceGate(
                    id: "QC.TESTS",
                    status: .pass,
                    message: "Tests allegedly passed.",
                    commandID: "static"
                )
            ],
            artifacts: []
        )
        let expected = expectation(
            commands: [
                "static": EvidenceCommandExpectation(
                    commandSHA256: staticCommandHash,
                    exitCode: 0
                ),
                "tests": EvidenceCommandExpectation(
                    commandSHA256: testsCommandHash,
                    exitCode: 0,
                    actions: [.localTestExecution]
                )
            ],
            gates: [
                "QC.STATIC": EvidenceGateExpectation(
                    commandID: "static",
                    status: .pass,
                    message: "Static passed."
                ),
                "QC.TESTS": EvidenceGateExpectation(
                    commandID: "tests",
                    actions: [.localTestExecution],
                    status: .pass,
                    message: "Tests passed."
                )
            ],
            userAuthorizedActions: [.localTestExecution],
            artifacts: [:]
        )

        let result = EvidenceVerifier.verify(evidence, expected: expected)

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.GATE_SET_MISMATCH"))
    }

    @Test("Every command must be accounted for by a gate")
    func unaccountedFailedCommandIsBypassed() {
        let evidence = validEvidence(
            commands: [
                EvidenceCommand(
                    id: "static",
                    commandSHA256: staticCommandHash,
                    exitCode: 0
                ),
                EvidenceCommand(
                    id: "auxiliary",
                    commandSHA256: auxiliaryCommandHash,
                    exitCode: 1
                )
            ],
            gates: [
                EvidenceGate(
                    id: "QC.STATIC",
                    status: .pass,
                    message: "Static passed.",
                    commandID: "static"
                )
            ],
            artifacts: []
        )
        let expected = expectation(
            commands: [
                "static": EvidenceCommandExpectation(
                    commandSHA256: staticCommandHash,
                    exitCode: 0
                ),
                "auxiliary": EvidenceCommandExpectation(
                    commandSHA256: auxiliaryCommandHash,
                    exitCode: 1
                )
            ],
            gates: [
                "QC.STATIC": EvidenceGateExpectation(
                    commandID: "static",
                    status: .pass,
                    message: "Static passed."
                )
            ],
            artifacts: [:]
        )

        let result = EvidenceVerifier.verify(evidence, expected: expected)

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.UNACCOUNTED_COMMAND"))
    }

    @Test("Every command requires a terminal exit code")
    func commandWithoutExitCodeDoesNotDecode() {
        let json = Data(
            #"{"id":"static","commandSHA256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","actions":[],"authorization":"NOT_REQUIRED"}"#.utf8
        )

        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(EvidenceCommand.self, from: json)
        }
    }

    @Test("A non-executed gate cannot upgrade its trusted status")
    func nonExecutedGateStatusUpgradeIsBypassed() {
        let evidence = validEvidence(
            gates: [
                EvidenceGate(
                    id: "QC.STATIC",
                    status: .pass,
                    message: "Static passed.",
                    commandID: "static"
                ),
                EvidenceGate(
                    id: "QC.UI_TESTS",
                    status: .notApplicable,
                    message: "UI tests were declared not applicable.",
                    actions: [.uiTests]
                )
            ]
        )
        let expected = expectation(
            gates: [
                "QC.STATIC": EvidenceGateExpectation(
                    commandID: "static",
                    status: .pass,
                    message: "Static passed."
                ),
                "QC.UI_TESTS": EvidenceGateExpectation(
                    actions: [.uiTests],
                    status: .skipped,
                    message: "UI tests were declared not applicable."
                )
            ]
        )

        let result = EvidenceVerifier.verify(evidence, expected: expected)

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.GATE_SET_MISMATCH"))
    }

    @Test("An executed gate cannot upgrade its trusted status")
    func executedGateStatusUpgradeIsBypassed() {
        let result = EvidenceVerifier.verify(
            validEvidence(),
            expected: expectation(
                gates: [
                    "QC.STATIC": EvidenceGateExpectation(
                        commandID: "static",
                        status: .blocked,
                        message: "Static checks passed."
                    )
                ]
            )
        )

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.GATE_SET_MISMATCH"))
    }

    @Test("A gate cannot replace its trusted message")
    func forgedGateMessageIsBypassed() {
        let evidence = validEvidence(
            gates: [
                EvidenceGate(
                    id: "QC.STATIC",
                    status: .pass,
                    message: "Security and UI checks also passed.",
                    commandID: "static"
                )
            ]
        )

        let result = EvidenceVerifier.verify(evidence, expected: expectation())

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.GATE_SET_MISMATCH"))
    }

    @Test("Missing expected gate evidence is BYPASSED")
    func missingGateIsBypassed() {
        let result = EvidenceVerifier.verify(
            validEvidence(),
            expected: expectation(
                gates: [
                    "QC.STATIC": EvidenceGateExpectation(
                        commandID: "static",
                        status: .pass,
                        message: "Static checks passed."
                    ),
                    "QC.TESTS": EvidenceGateExpectation(
                        actions: [.localTestExecution],
                        status: .notRunByUserDecision,
                        message: "Tests were not run by user decision."
                    )
                ]
            )
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
                    commandSHA256: staticCommandHash,
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

    @Test("Untrusted test counts cannot overflow the verifier")
    func overflowingTestCountsAreBypassed() {
        let counts = EvidenceTestCounts(
            total: 0,
            passed: .max,
            failed: 1,
            skipped: 0
        )
        let evidence = validEvidence(testCounts: counts)

        let result = EvidenceVerifier.verify(
            evidence,
            expected: expectation(testCounts: counts, testGateID: "QC.STATIC")
        )

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.INVALID_TEST_COUNTS"))
    }

    @Test("Trusted failed test counts cannot verify as READY")
    func failedTestCountsRejectReady() {
        let counts = EvidenceTestCounts(total: 1, passed: 0, failed: 1, skipped: 0)
        let evidence = validEvidence(testCounts: counts)

        let result = EvidenceVerifier.verify(
            evidence,
            expected: expectation(testCounts: counts, testGateID: "QC.STATIC")
        )

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.TEST_COUNT_GATE_MISMATCH"))
    }

    @Test("All-skipped test counts require a blocked gate")
    func allSkippedTestCountsRejectPass() {
        let counts = EvidenceTestCounts(total: 1, passed: 0, failed: 0, skipped: 1)
        let evidence = validEvidence(testCounts: counts)

        let result = EvidenceVerifier.verify(
            evidence,
            expected: expectation(testCounts: counts, testGateID: "QC.STATIC")
        )

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.TEST_COUNT_GATE_MISMATCH"))
    }

    @Test("Oversized top-level collections stop before deeper scans")
    func collectionLimitReturnsBeforeDuplicateScan() {
        let commands = (0...64).map { _ in
            EvidenceCommand(
                id: "duplicate",
                commandSHA256: staticCommandHash,
                exitCode: 0
            )
        }
        let evidence = validEvidence(commands: commands)

        let result = EvidenceVerifier.verify(evidence, expected: expectation())

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code) == ["QC.EVIDENCE.COLLECTION_LIMIT"])
    }

    @Test("PASS evidence requires a zero command exit code")
    func passWithNonzeroExitIsBypassed() {
        let evidence = validEvidence(
            commands: [
                EvidenceCommand(
                    id: "static",
                    commandSHA256: staticCommandHash,
                    exitCode: 1
                )
            ]
        )

        let result = EvidenceVerifier.verify(
            evidence,
            expected: expectation(
                commands: [
                    "static": EvidenceCommandExpectation(
                        commandSHA256: staticCommandHash,
                        exitCode: 1
                    )
                ]
            )
        )

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
            expected: expectation(
                gates: [
                    "QC.TESTS": EvidenceGateExpectation(
                        status: .skipped,
                        message: "Job did not run."
                    )
                ]
            )
        )

        #expect(result.verdict == .bypassed)
        #expect(result.issues.map(\.code).contains("QC.EVIDENCE.CLAIMED_VERDICT_MISMATCH"))
    }

    @Test("Commandless non-execution evidence preserves its advisory outcome")
    func commandlessNonExecutionIsRepresentable() {
        let declined = validEvidence(
            commands: [],
            gates: [
                EvidenceGate(
                    id: "QC.TESTS",
                    status: .notRunByUserDecision,
                    message: "Tests were declined before execution.",
                    actions: [.localTestExecution]
                )
            ],
            claimedVerdict: .needsOwnerDecision
        )
        let unavailable = validEvidence(
            commands: [],
            gates: [
                EvidenceGate(
                    id: "QC.TOOLCHAIN",
                    status: .blocked,
                    message: "Required toolchain is unavailable."
                )
            ],
            claimedVerdict: .blocked
        )

        let declinedResult = EvidenceVerifier.verify(
            declined,
            expected: expectation(
                commands: [:],
                gates: [
                    "QC.TESTS": EvidenceGateExpectation(
                        actions: [.localTestExecution],
                        status: .notRunByUserDecision,
                        message: "Tests were declined before execution."
                    )
                ]
            )
        )
        let unavailableResult = EvidenceVerifier.verify(
            unavailable,
            expected: expectation(
                commands: [:],
                gates: [
                    "QC.TOOLCHAIN": EvidenceGateExpectation(
                        status: .blocked,
                        message: "Required toolchain is unavailable."
                    )
                ]
            )
        )

        #expect(declinedResult.verdict == .needsOwnerDecision)
        #expect(declinedResult.issues.isEmpty)
        #expect(unavailableResult.verdict == .blocked)
        #expect(unavailableResult.issues.isEmpty)
    }

    @Test("Evidence has a stable encoded representation and bounded loader")
    func evidenceRoundTrip() throws {
        let evidence = validEvidence()
        let encoded = try JSONEncoder().encode(evidence)
        let decoded = try EvidenceLoader.decode(encoded)
        let object = try #require(
            try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        let commands = try #require(object["commands"] as? [[String: Any]])
        let command = try #require(commands.first)

        #expect(decoded.schemaVersion == 1)
        #expect(decoded.sourceRevision == sourceRevision)
        #expect(decoded.gates.map(\.status) == [.pass])
        #expect(decoded.claimedVerdict == .ready)
        #expect(command["commandLine"] == nil)
        #expect(command["commandSHA256"] as? String == staticCommandHash)
    }

    @Test("Evidence loader rejects schema-invalid properties, null optionals, and duplicate keys")
    func strictEvidenceDecodingRejectsSchemaInvalidJSON() throws {
        let encoded = try JSONEncoder().encode(validEvidence())
        let baseObject = try #require(
            try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )

        var unknownTopLevel = baseObject
        unknownTopLevel["unexpected"] = true

        var unknownNested = baseObject
        var commands = try #require(unknownNested["commands"] as? [[String: Any]])
        commands[0]["unexpected"] = true
        unknownNested["commands"] = commands

        var nullOptional = baseObject
        nullOptional["testCounts"] = NSNull()

        for object in [unknownTopLevel, unknownNested, nullOptional] {
            let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            #expect(throws: DecodingError.self) {
                try EvidenceLoader.decode(data)
            }
        }

        let encodedString = try #require(String(data: encoded, encoding: .utf8))
        let openingBrace = try #require(encodedString.firstIndex(of: "{"))
        let duplicateSchemaVersion = encodedString.replacingCharacters(
            in: openingBrace...openingBrace,
            with: #"{"schemaVersion":1,"#
        )
        #expect(throws: Error.self) {
            try EvidenceLoader.decode(Data(duplicateSchemaVersion.utf8))
        }
    }

    @Test("Runtime string limits use schema Unicode-length units")
    func unicodeStringBoundsMatchSchema() {
        let acceptedMessage = String(repeating: "é", count: 1_024)
        let rejectedMessage = String(repeating: "é", count: 1_025)
        let whitespaceOnlyMessage = String(repeating: "\u{200B}", count: 8)
        let accepted = validEvidence(
            gates: [
                EvidenceGate(
                    id: "QC.STATIC",
                    status: .pass,
                    message: acceptedMessage,
                    commandID: "static"
                )
            ]
        )
        let rejected = validEvidence(
            gates: [
                EvidenceGate(
                    id: "QC.STATIC",
                    status: .pass,
                    message: rejectedMessage,
                    commandID: "static"
                )
            ]
        )
        let whitespaceOnly = validEvidence(
            gates: [
                EvidenceGate(
                    id: "QC.STATIC",
                    status: .pass,
                    message: whitespaceOnlyMessage,
                    commandID: "static"
                )
            ]
        )

        let acceptedResult = EvidenceVerifier.verify(
            accepted,
            expected: expectation(
                gates: [
                    "QC.STATIC": EvidenceGateExpectation(
                        commandID: "static",
                        status: .pass,
                        message: acceptedMessage
                    )
                ]
            )
        )
        let rejectedResult = EvidenceVerifier.verify(
            rejected,
            expected: expectation(
                gates: [
                    "QC.STATIC": EvidenceGateExpectation(
                        commandID: "static",
                        status: .pass,
                        message: rejectedMessage
                    )
                ]
            )
        )
        let whitespaceOnlyResult = EvidenceVerifier.verify(
            whitespaceOnly,
            expected: expectation(
                gates: [
                    "QC.STATIC": EvidenceGateExpectation(
                        commandID: "static",
                        status: .pass,
                        message: whitespaceOnlyMessage
                    )
                ]
            )
        )

        #expect(acceptedResult.verdict == .ready)
        #expect(acceptedResult.issues.isEmpty)
        #expect(rejectedResult.verdict == .bypassed)
        #expect(rejectedResult.issues.map(\.code) == ["QC.EVIDENCE.STRING_LIMIT"])
        #expect(whitespaceOnlyResult.verdict == .bypassed)
        #expect(whitespaceOnlyResult.issues.map(\.code) == ["QC.EVIDENCE.STRING_LIMIT"])
    }

    @Test("Schema constraints match runtime evidence rules")
    func schemaConstraintsMatchRuntime() throws {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let schemaURL = repositoryRoot.appendingPathComponent(
            "schemas/quality-evidence.schema.json"
        )
        let schema = try #require(
            try JSONSerialization.jsonObject(with: Data(contentsOf: schemaURL))
                as? [String: Any]
        )
        let definitions = try #require(schema["$defs"] as? [String: Any])
        let properties = try #require(schema["properties"] as? [String: Any])
        let commandCollection = try #require(properties["commands"] as? [String: Any])
        let commandSchema = try #require(commandCollection["items"] as? [String: Any])
        let commandProperties = try #require(commandSchema["properties"] as? [String: Any])
        let commandRequired = try #require(commandSchema["required"] as? [String])
        let commandConditions = try #require(commandSchema["allOf"] as? [[String: Any]])
        #expect(commandProperties["commandLine"] == nil)
        #expect(commandProperties["commandSHA256"] != nil)
        #expect(commandRequired.contains("commandSHA256"))
        #expect(commandCollection["minItems"] == nil)
        #expect(commandCollection["uniqueItems"] as? Bool == true)
        #expect(commandConditions.count == 2)

        let actionlessIf = try #require(commandConditions[0]["if"] as? [String: Any])
        let actionlessProperties = try #require(actionlessIf["properties"] as? [String: Any])
        let actionlessActions = try #require(actionlessProperties["actions"] as? [String: Any])
        let actionlessThen = try #require(commandConditions[0]["then"] as? [String: Any])
        let actionlessThenProperties = try #require(
            actionlessThen["properties"] as? [String: Any]
        )
        let actionlessAuthorization = try #require(
            actionlessThenProperties["authorization"] as? [String: Any]
        )
        #expect(actionlessActions["maxItems"] as? Int == 0)
        #expect(actionlessAuthorization["const"] as? String == "NOT_REQUIRED")

        let controlledIf = try #require(commandConditions[1]["if"] as? [String: Any])
        let controlledProperties = try #require(controlledIf["properties"] as? [String: Any])
        let controlledActions = try #require(controlledProperties["actions"] as? [String: Any])
        let controlledThen = try #require(commandConditions[1]["then"] as? [String: Any])
        let controlledThenProperties = try #require(
            controlledThen["properties"] as? [String: Any]
        )
        let controlledAuthorization = try #require(
            controlledThenProperties["authorization"] as? [String: Any]
        )
        let controlledAuthorizations = try #require(
            controlledAuthorization["enum"] as? [String]
        )
        #expect(controlledActions["minItems"] as? Int == 1)
        #expect(Set(controlledAuthorizations) == Set(["PROFILE", "USER"]))

        let gateCollection = try #require(properties["gates"] as? [String: Any])
        let gateSchema = try #require(gateCollection["items"] as? [String: Any])
        let gateConditions = try #require(gateSchema["allOf"] as? [[String: Any]])
        #expect(gateConditions.count == 3)
        #expect(gateCollection["uniqueItems"] as? Bool == true)

        let executedIf = try #require(gateConditions[0]["if"] as? [String: Any])
        let executedProperties = try #require(executedIf["properties"] as? [String: Any])
        let executedStatus = try #require(executedProperties["status"] as? [String: Any])
        let executedStatuses = try #require(executedStatus["enum"] as? [String])
        let executedThen = try #require(gateConditions[0]["then"] as? [String: Any])
        #expect(Set(executedStatuses) == Set(["PASS", "FAIL"]))
        #expect(executedThen["required"] as? [String] == ["commandID"])

        let nonExecutedIf = try #require(gateConditions[1]["if"] as? [String: Any])
        let nonExecutedProperties = try #require(
            nonExecutedIf["properties"] as? [String: Any]
        )
        let nonExecutedStatus = try #require(
            nonExecutedProperties["status"] as? [String: Any]
        )
        let nonExecutedStatuses = try #require(nonExecutedStatus["enum"] as? [String])
        let nonExecutedThen = try #require(
            gateConditions[1]["then"] as? [String: Any]
        )
        let forbiddenCommandID = try #require(nonExecutedThen["not"] as? [String: Any])
        #expect(
            Set(nonExecutedStatuses)
                == Set(["NOT_APPLICABLE", "NOT_RUN_BY_USER_DECISION", "SKIPPED"])
        )
        #expect(forbiddenCommandID["required"] as? [String] == ["commandID"])

        let userDecisionIf = try #require(gateConditions[2]["if"] as? [String: Any])
        let userDecisionProperties = try #require(
            userDecisionIf["properties"] as? [String: Any]
        )
        let userDecisionStatus = try #require(
            userDecisionProperties["status"] as? [String: Any]
        )
        let userDecisionThen = try #require(
            gateConditions[2]["then"] as? [String: Any]
        )
        let userDecisionThenProperties = try #require(
            userDecisionThen["properties"] as? [String: Any]
        )
        let userDecisionActions = try #require(
            userDecisionThenProperties["actions"] as? [String: Any]
        )
        #expect(userDecisionStatus["const"] as? String == "NOT_RUN_BY_USER_DECISION")
        #expect(userDecisionActions["minItems"] as? Int == 1)

        let profileSchemaVersion = try #require(
            properties["profileSchemaVersion"] as? [String: Any]
        )
        #expect(profileSchemaVersion["const"] as? Int == 1)

        let residualRisks = try #require(properties["residualRisks"] as? [String: Any])
        let artifacts = try #require(properties["artifacts"] as? [String: Any])
        let nonEmptyString = try #require(definitions["nonEmptyString"] as? [String: Any])
        let maximumCollectionItems = try #require(commandCollection["maxItems"] as? Int)
        let maximumStringScalars = try #require(nonEmptyString["maxLength"] as? Int)
        #expect(artifacts["uniqueItems"] as? Bool == true)
        #expect(residualRisks["uniqueItems"] as? Bool == true)
        #expect(maximumCollectionItems == 64)
        #expect(gateCollection["maxItems"] as? Int == maximumCollectionItems)
        #expect(artifacts["maxItems"] as? Int == maximumCollectionItems)
        #expect(residualRisks["maxItems"] as? Int == maximumCollectionItems)
        #expect(maximumStringScalars == 1_024)

        let nonWhitespacePattern = try #require(nonEmptyString["pattern"] as? String)
        let zeroWidthSpaces = String(repeating: "\u{200B}", count: 2)
        let zeroWidthRange = NSRange(
            zeroWidthSpaces.startIndex..<zeroWidthSpaces.endIndex,
            in: zeroWidthSpaces
        )
        #expect(
            try NSRegularExpression(pattern: nonWhitespacePattern)
                .firstMatch(in: zeroWidthSpaces, range: zeroWidthRange) == nil
        )

        let maximumStringSlots = 4
            + maximumCollectionItems
            + (3 * maximumCollectionItems)
            + maximumCollectionItems
            + maximumCollectionItems
        let conservativeEscapedStringBytes = maximumStringSlots
            * maximumStringScalars
            * 12
        let structuralAllowanceBytes = 1_000_000
        #expect(
            conservativeEscapedStringBytes + structuralAllowanceBytes
                < EvidenceLoader.maximumDocumentBytes
        )

        let relativePath = try #require(definitions["relativePath"] as? [String: Any])
        let clauses = try #require(relativePath["allOf"] as? [[String: Any]])
        let patterns = clauses.compactMap { clause in
            (clause["not"] as? [String: Any])?["pattern"] as? String
        }

        func isRejected(_ path: String) throws -> Bool {
            let range = NSRange(path.startIndex..<path.endIndex, in: path)
            return try patterns.contains { pattern in
                try NSRegularExpression(pattern: pattern)
                    .firstMatch(in: path, range: range) != nil
            }
        }

        for path in [".", "reports//result.json", "reports/"] {
            #expect(try isRejected(path))
        }
        #expect(try !isRejected("reports/result.json"))
    }

    private func validEvidence(
        profileSchemaVersion: Int = 1,
        permissions: PermissionPolicy? = nil,
        commands: [EvidenceCommand]? = nil,
        gates: [EvidenceGate]? = nil,
        testCounts: EvidenceTestCounts? = nil,
        reviewRevision: String? = nil,
        artifacts: [EvidenceArtifact]? = nil,
        residualRisks: [String] = [],
        claimedVerdict: AdvisoryVerdict = .ready
    ) -> QualityEvidence {
        QualityEvidence(
            sourceRepository: "MArtem/AIZenflowQualityControl",
            sourceRevision: sourceRevision,
            engineVersion: "0.1.0",
            engineRevision: engineRevision,
            profileSchemaVersion: profileSchemaVersion,
            profileSHA256: profileHash,
            toolchain: toolchain,
            permissions: permissions ?? policy,
            commands: commands ?? [
                EvidenceCommand(
                    id: "static",
                    commandSHA256: staticCommandHash,
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
            testCounts: testCounts,
            reviewRevision: reviewRevision,
            artifacts: artifacts ?? [
                EvidenceArtifact(path: "reports/static.json", sha256: artifactHash)
            ],
            residualRisks: residualRisks,
            claimedVerdict: claimedVerdict
        )
    }

    private func expectation(
        sourceRevision: String? = nil,
        profileSchemaVersion: Int = 1,
        artifactHash: String? = nil,
        commands: [String: EvidenceCommandExpectation]? = nil,
        gates: [String: EvidenceGateExpectation]? = nil,
        userAuthorizedActions: Set<PermissionAction> = [],
        testCounts: EvidenceTestCounts? = nil,
        testGateID: String? = nil,
        artifacts: [String: String]? = nil,
        residualRisks: Set<String> = []
    ) -> EvidenceExpectation {
        EvidenceExpectation(
            sourceRepository: "MArtem/AIZenflowQualityControl",
            sourceRevision: sourceRevision ?? self.sourceRevision,
            engineVersion: "0.1.0",
            engineRevision: engineRevision,
            profileSchemaVersion: profileSchemaVersion,
            profileSHA256: profileHash,
            toolchain: toolchain,
            permissions: policy,
            commandsByID: commands ?? [
                "static": EvidenceCommandExpectation(
                    commandSHA256: staticCommandHash,
                    exitCode: 0
                )
            ],
            gatesByID: gates ?? [
                "QC.STATIC": EvidenceGateExpectation(
                    commandID: "static",
                    status: .pass,
                    message: "Static checks passed."
                )
            ],
            userAuthorizedActions: userAuthorizedActions,
            testCounts: testCounts,
            testGateID: testGateID,
            artifactSHA256ByPath: artifacts ?? [
                "reports/static.json": artifactHash ?? self.artifactHash
            ],
            residualRisks: residualRisks
        )
    }
}
