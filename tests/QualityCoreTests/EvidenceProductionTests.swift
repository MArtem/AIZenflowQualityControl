import CryptoKit
import Foundation
import Testing
@testable import QualityCore

@Suite("Evidence production")
struct EvidenceProductionTests {
    private let sourceRevision = String(repeating: "a", count: 40)
    private let engineRevision = String(repeating: "b", count: 40)
    private let commandHash = String(repeating: "c", count: 64)

    @Test("A valid completed static run produces structurally verifiable READY evidence")
    func validStaticRunProducesReadyEvidence() throws {
        let snapshot = profileSnapshot()
        let context = validContext()
        let expected = trustedExpectation(for: context, profileSnapshot: snapshot)

        let evidence = try EvidenceProducer.produce(
            context: context,
            profileSnapshot: snapshot,
            expected: expected
        )
        let verification = EvidenceVerifier.verify(evidence, expected: expected)

        #expect(evidence.artifacts.isEmpty)
        #expect(evidence.claimedVerdict == .ready)
        #expect(verification.verdict == .ready)
        #expect(verification.issues.isEmpty)
    }

    @Test("Failure, blocked and user-declined gates retain conservative verdicts")
    func conservativeGateVerdicts() throws {
        for (status, expected) in [
            (GateStatus.fail, AdvisoryVerdict.notReady),
            (.blocked, .blocked),
            (.notRunByUserDecision, .needsOwnerDecision)
        ] {
            let context = validContext(status: status)
            let evidence = try produce(context: context)
            #expect(evidence.claimedVerdict == expected)
        }
    }

    @Test("Residual risk prevents READY")
    func residualRiskPreventsReady() throws {
        let evidence = try produce(
            context: validContext(residualRisks: ["Artifact snapshot attestation is unavailable."])
        )

        #expect(evidence.claimedVerdict == .needsOwnerDecision)
    }

    @Test("A snapshot hash is computed from the exact decoded profile bytes")
    func profileSnapshotHashMatchesBytes() throws {
        let data = profileJSON().data(using: .utf8)!
        let expectedHash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        let url = try temporaryFile(data: data)
        defer { try? FileManager.default.removeItem(at: url) }

        let snapshot = try ProfileLoader.loadSnapshot(from: url)

        #expect(snapshot.sha256 == expectedHash)
        #expect(snapshot.profile.schemaVersion == 1)
    }

    @Test("Unauthorized actions cannot be produced as evidence")
    func authorizationMismatchIsRejected() {
        let context = EvidenceProductionContext(
            sourceRepository: "MArtem/example",
            sourceRevision: sourceRevision,
            engineVersion: "1.0.0",
            engineRevision: engineRevision,
            toolchain: toolchain,
            commands: [
                EvidenceCommand(
                    id: "tests",
                    commandSHA256: commandHash,
                    exitCode: 0,
                    actions: [.localTestExecution],
                    authorization: .profile
                )
            ],
            gates: [
                EvidenceGate(
                    id: "QC.TESTS",
                    status: .pass,
                    message: "Tests passed.",
                    commandID: "tests",
                    actions: [.localTestExecution]
                )
            ]
        )

        #expect(throws: EvidenceProductionError.self) {
            try produce(context: context)
        }
    }

    @Test("Trusted authorization is supplied outside the untrusted context")
    func trustedAuthorizationCanProduceEvidence() throws {
        let context = EvidenceProductionContext(
            sourceRepository: "MArtem/example",
            sourceRevision: sourceRevision,
            engineVersion: "1.0.0",
            engineRevision: engineRevision,
            toolchain: toolchain,
            commands: [
                EvidenceCommand(
                    id: "tests",
                    commandSHA256: commandHash,
                    exitCode: 0,
                    actions: [.localTestExecution],
                    authorization: .user
                )
            ],
            gates: [
                EvidenceGate(
                    id: "QC.TESTS",
                    status: .pass,
                    message: "Tests passed.",
                    commandID: "tests",
                    actions: [.localTestExecution]
                )
            ]
        )

        let evidence = try produce(
            context: context,
            userAuthorizedActions: [.localTestExecution]
        )

        #expect(evidence.claimedVerdict == .ready)
    }

    @Test("Malformed, unknown, duplicate and null context JSON is rejected")
    func unsafeContextJSONIsRejected() {
        for document in [
            "{}",
            validContextJSON.replacingOccurrences(of: "\"residualRisks\":[]", with: "\"unknown\":true,\"residualRisks\":[]"),
            validContextJSON.replacingOccurrences(of: "\"sourceRepository\":\"MArtem/example\"", with: "\"sourceRepository\":\"MArtem/example\",\"sourceRepository\":\"forged\""),
            validContextJSON.replacingOccurrences(of: "\"residualRisks\":[]", with: "\"residualRisks\":null")
        ] {
            #expect(throws: (any Error).self) {
                try EvidenceProductionContextLoader.decode(Data(document.utf8))
            }
        }
    }

    @Test("Inconsistent test count context is rejected")
    func inconsistentTestCountsAreRejected() {
        let context = validContext(
            testCounts: EvidenceTestCounts(total: 2, passed: 2, failed: 1, skipped: 0),
            testGateID: "QC.STATIC"
        )

        #expect(throws: EvidenceProductionError.self) {
            try produce(context: context)
        }
    }

    @Test("A passing gate cannot claim a nonzero command exit")
    func passingGateWithNonzeroExitIsRejected() {
        let context = EvidenceProductionContext(
            sourceRepository: "MArtem/example",
            sourceRevision: sourceRevision,
            engineVersion: "1.0.0",
            engineRevision: engineRevision,
            toolchain: toolchain,
            commands: [EvidenceCommand(id: "static", commandSHA256: commandHash, exitCode: 1)],
            gates: [
                EvidenceGate(
                    id: "QC.STATIC",
                    status: .pass,
                    message: "Static analysis completed.",
                    commandID: "static"
                )
            ]
        )

        #expect(throws: EvidenceProductionError.self) {
            try produce(context: context)
        }
    }

    @Test("Oversized context JSON is rejected before decoding")
    func oversizedContextIsRejected() {
        #expect(throws: (any Error).self) {
            try EvidenceProductionContextLoader.decode(
                Data(repeating: 0x20, count: EvidenceProductionContextLoader.maximumDocumentBytes + 1)
            )
        }
    }

    @Test("Public context construction cannot bypass collection limits")
    func oversizedPublicContextIsRejectedBeforeExpectationBuilding() {
        let context = EvidenceProductionContext(
            sourceRepository: "MArtem/example",
            sourceRevision: sourceRevision,
            engineVersion: "1.0.0",
            engineRevision: engineRevision,
            toolchain: toolchain,
            commands: Array(repeating: EvidenceCommand(id: "static", commandSHA256: commandHash, exitCode: 0), count: 65),
            gates: []
        )

        #expect(throws: EvidenceProductionError.self) {
            _ = try EvidenceProducer.produce(
                context: context,
                profileSnapshot: profileSnapshot(),
                expected: trustedExpectation(for: validContext(), profileSnapshot: profileSnapshot())
            )
        }
    }

    @Test("Semantically invalid profiles cannot produce evidence")
    func invalidProfileIsRejected() {
        #expect(throws: EvidenceProductionError.self) {
            let snapshot = profileSnapshot(root: ".", cache: ".quality-control-cache")
            _ = try EvidenceProducer.produce(
                context: validContext(),
                profileSnapshot: snapshot,
                expected: trustedExpectation(for: validContext(), profileSnapshot: snapshot)
            )
        }
    }

    @Test("Untrusted context outcomes cannot satisfy a trusted expectation")
    func untrustedOutcomeCannotProduceReadyEvidence() {
        let trustedContext = validContext()
        let snapshot = profileSnapshot()
        let untrustedContext = validContext(status: .fail)

        #expect(throws: EvidenceProductionError.self) {
            try EvidenceProducer.produce(
                context: untrustedContext,
                profileSnapshot: snapshot,
                expected: trustedExpectation(for: trustedContext, profileSnapshot: snapshot)
            )
        }
    }

    private var toolchain: EvidenceToolchain {
        EvidenceToolchain(swiftVersion: "Swift 6", xcodeVersion: "Xcode 16")
    }

    private func validContext(
        status: GateStatus = .pass,
        residualRisks: [String] = [],
        testCounts: EvidenceTestCounts? = nil,
        testGateID: String? = nil
    ) -> EvidenceProductionContext {
        EvidenceProductionContext(
            sourceRepository: "MArtem/example",
            sourceRevision: sourceRevision,
            engineVersion: "1.0.0",
            engineRevision: engineRevision,
            toolchain: toolchain,
            commands: (status == .pass || status == .fail) ? [
                EvidenceCommand(id: "static", commandSHA256: commandHash, exitCode: status == .fail ? 1 : 0)
            ] : [],
            gates: [
                EvidenceGate(
                    id: "QC.STATIC",
                    status: status,
                    message: "Static analysis completed.",
                    commandID: status == .pass || status == .fail ? "static" : nil,
                    actions: status == .notRunByUserDecision ? [.localTestExecution] : []
                )
            ],
            testCounts: testCounts,
            testGateID: testGateID,
            residualRisks: residualRisks
        )
    }

    private func profileSnapshot(
        root: String = "/sandbox",
        cache: String = "/sandbox/cache"
    ) -> ProfileSnapshot {
        try! ProfileSnapshot(data: Data(profileJSON(root: root, cache: cache).utf8))
    }

    private func produce(
        context: EvidenceProductionContext,
        profileSnapshot: ProfileSnapshot? = nil,
        userAuthorizedActions: Set<PermissionAction> = []
    ) throws -> QualityEvidence {
        let snapshot = profileSnapshot ?? self.profileSnapshot()
        return try EvidenceProducer.produce(
            context: context,
            profileSnapshot: snapshot,
            expected: trustedExpectation(
                for: context,
                profileSnapshot: snapshot,
                userAuthorizedActions: userAuthorizedActions
            )
        )
    }

    private func trustedExpectation(
        for context: EvidenceProductionContext,
        profileSnapshot: ProfileSnapshot,
        userAuthorizedActions: Set<PermissionAction> = []
    ) -> EvidenceExpectation {
        let commands = Dictionary(
            uniqueKeysWithValues: context.commands.map {
                ($0.id, EvidenceCommandExpectation(
                    commandSHA256: $0.commandSHA256,
                    exitCode: $0.exitCode,
                    actions: Set($0.actions)
                ))
            }
        )
        let gates = Dictionary(
            uniqueKeysWithValues: context.gates.map {
                ($0.id, EvidenceGateExpectation(
                    commandID: $0.commandID,
                    actions: Set($0.actions),
                    status: $0.status,
                    message: $0.message
                ))
            }
        )
        return EvidenceExpectation(
            sourceRepository: context.sourceRepository,
            sourceRevision: context.sourceRevision,
            engineVersion: context.engineVersion,
            engineRevision: context.engineRevision,
            profileSchemaVersion: profileSnapshot.profile.schemaVersion,
            profileSHA256: profileSnapshot.sha256,
            toolchain: context.toolchain,
            permissions: profileSnapshot.profile.permissions,
            commandsByID: commands,
            gatesByID: gates,
            userAuthorizedActions: userAuthorizedActions,
            testCounts: context.testCounts,
            testGateID: context.testGateID,
            reviewRevision: context.reviewRevision,
            artifactSHA256ByPath: [:],
            residualRisks: Set(context.residualRisks)
        )
    }

    private func temporaryFile(data: Data) throws -> URL {
        let directory = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(".quality-control-cache/test-fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent(UUID().uuidString)
        try data.write(to: url, options: .atomic)
        return url
    }

    private func profileJSON(
        root: String = "/sandbox",
        cache: String = "/sandbox/cache"
    ) -> String {
        """
        {"schemaVersion":1,"project":{"kind":"xcodeproj","path":"App.xcodeproj"},"scheme":"App","sourcePaths":["Sources"],"mode":"controlled","permissions":{"testCreation":"allow","testModification":"allow","localTestExecution":"ask","githubExecution":"manual","uiTests":"deny","simulatorOrDevice":"deny","performanceOrInstruments":"deny"},"sandbox":{"root":"\(root)","cache":"\(cache)"}}
        """
    }

    private var validContextJSON: String {
        """
        {"sourceRepository":"MArtem/example","sourceRevision":"\(sourceRevision)","engineVersion":"1.0.0","engineRevision":"\(engineRevision)","toolchain":{"swiftVersion":"Swift 6","xcodeVersion":"Xcode 16"},"commands":[{"id":"static","commandSHA256":"\(commandHash)","exitCode":0,"actions":[],"authorization":"NOT_REQUIRED"}],"gates":[{"id":"QC.STATIC","status":"PASS","message":"Static analysis completed.","commandID":"static","actions":[]}],"residualRisks":[]}
        """
    }
}
