import Foundation
import Testing
@testable import QualityCore

@Suite("Static evidence coordination contracts")
struct StaticEvidenceCoordinatorTests {
    @Test(
        "A validated static result produces the matching evidence gate and verdict",
        arguments: [
            StaticEvidenceCase(
                status: .pass,
                expectedGateStatus: .pass,
                expectedVerdict: .ready,
                expectedExitCode: 0
            ),
            StaticEvidenceCase(
                status: .fail,
                expectedGateStatus: .fail,
                expectedVerdict: .notReady,
                expectedExitCode: 1
            ),
            StaticEvidenceCase(
                status: .blocked,
                expectedGateStatus: .blocked,
                expectedVerdict: .blocked,
                expectedExitCode: 2
            )
        ]
    )
    func mapsValidatedStaticStatus(_ input: StaticEvidenceCase) throws {
        let snapshot = try validProfileSnapshot()
        let receipt = try StaticEvidenceCoordinator.coordinate(
            observation: try observation(
                status: input.status,
                profileSHA256: snapshot.sha256,
                policySHA256: policySHA256
            ),
            context: context(profileSnapshot: snapshot)
        )

        #expect(receipt.report.status == input.status)
        #expect(receipt.evidence.commands.count == 1)
        #expect(receipt.evidence.commands[0].id == "static")
        #expect(receipt.evidence.commands[0].exitCode == input.expectedExitCode)
        #expect(receipt.evidence.commands[0].actions.isEmpty)
        #expect(receipt.evidence.commands[0].authorization == .notRequired)
        #expect(receipt.evidence.gates.count == 1)
        #expect(receipt.evidence.gates[0].id == "QC.STATIC")
        #expect(receipt.evidence.gates[0].status == input.expectedGateStatus)
        #expect(receipt.evidence.gates[0].commandID == "static")
        #expect(receipt.evidence.claimedVerdict == input.expectedVerdict)
        #expect(receipt.verification.verdict == input.expectedVerdict)
        #expect(receipt.verification.issues.isEmpty)
    }

    @Test("A worker profile digest must bind the exact supplied profile snapshot")
    func profileDigestMismatchFailsClosed() throws {
        let snapshot = try validProfileSnapshot()

        #expect(throws: StaticEvidenceCoordinationError.self) {
            try StaticEvidenceCoordinator.coordinate(
                observation: try observation(
                    status: .pass,
                    profileSHA256: String(repeating: "c", count: 64),
                    policySHA256: policySHA256
                ),
                context: context(profileSnapshot: snapshot)
            )
        }
    }

    @Test("A worker policy digest must bind the exact parent-observed policy snapshot")
    func policyDigestMismatchFailsClosed() throws {
        let snapshot = try validProfileSnapshot()

        #expect(throws: StaticEvidenceCoordinationError.self) {
            try StaticEvidenceCoordinator.coordinate(
                observation: try observation(
                    status: .pass,
                    profileSHA256: snapshot.sha256,
                    policySHA256: String(repeating: "d", count: 64)
                ),
                context: context(profileSnapshot: snapshot)
            )
        }
    }

    @Test(
        "Missing worker snapshot bindings never produce evidence",
        arguments: MissingDigestCase.allCases
    )
    func missingDigestFailsClosed(_ input: MissingDigestCase) throws {
        let snapshot = try validProfileSnapshot()

        #expect(throws: StaticEvidenceCoordinationError.self) {
            try StaticEvidenceCoordinator.coordinate(
                observation: try input.observation(profileSHA256: snapshot.sha256),
                context: context(profileSnapshot: snapshot)
            )
        }
    }

    @Test("A structurally readable but semantically invalid profile cannot become evidence")
    func invalidProfileFailsClosed() throws {
        let snapshot = try ProfileSnapshot(
            data: Data(
                """
                {"schemaVersion":1,"project":{"kind":"xcodeproj","path":"App.xcodeproj"},"scheme":"App","sourcePaths":["Sources"],"mode":"controlled","permissions":{"testCreation":"allow","testModification":"allow","localTestExecution":"ask","githubExecution":"manual","uiTests":"deny","simulatorOrDevice":"deny","performanceOrInstruments":"deny"},"sandbox":{"root":".","cache":".quality-control-cache"}}
                """.utf8
            )
        )

        #expect(throws: StaticEvidenceCoordinationError.self) {
            try StaticEvidenceCoordinator.coordinate(
                observation: try observation(
                    status: .pass,
                    profileSHA256: snapshot.sha256,
                    policySHA256: policySHA256
                ),
                context: context(profileSnapshot: snapshot)
            )
        }
    }

    @Test(
        "Malformed or unbounded coordinator identity never produces evidence",
        arguments: InvalidContextCase.allCases
    )
    func invalidContextFailsClosed(_ input: InvalidContextCase) throws {
        let snapshot = try validProfileSnapshot()

        #expect(throws: StaticEvidenceCoordinationError.self) {
            try StaticEvidenceCoordinator.coordinate(
                observation: try observation(
                    status: .pass,
                    profileSHA256: snapshot.sha256,
                    policySHA256: policySHA256
                ),
                context: input.context(profileSnapshot: snapshot)
            )
        }
    }

    @Test("Command identity is deterministic and binds every static execution input")
    func commandIdentityBindsStaticInputs() throws {
        let snapshot = try validProfileSnapshot()
        let base = try coordinate(
            snapshot: snapshot,
            policySHA256: policySHA256
        )
        let changedPolicy = try coordinate(
            snapshot: snapshot,
            policySHA256: String(repeating: "d", count: 64)
        )
        let changedSource = try coordinate(
            snapshot: snapshot,
            policySHA256: policySHA256,
            sourceRevision: String(repeating: "e", count: 40)
        )
        let changedEngine = try coordinate(
            snapshot: snapshot,
            policySHA256: policySHA256,
            engineRevision: String(repeating: "f", count: 40)
        )
        let changedRepository = try coordinate(
            snapshot: snapshot,
            policySHA256: policySHA256,
            sourceRepository: "MArtem/other-example"
        )
        let changedProfile = try ProfileSnapshot(
            data: Data(validProfileJSON.replacingOccurrences(of: "App.xcodeproj", with: "Other.xcodeproj").utf8)
        )
        let changedProfileReceipt = try coordinate(
            snapshot: changedProfile,
            policySHA256: policySHA256
        )

        let baseHash = base.evidence.commands[0].commandSHA256
        #expect(baseHash != changedPolicy.evidence.commands[0].commandSHA256)
        #expect(baseHash != changedSource.evidence.commands[0].commandSHA256)
        #expect(baseHash != changedEngine.evidence.commands[0].commandSHA256)
        #expect(baseHash != changedRepository.evidence.commands[0].commandSHA256)
        #expect(baseHash != changedProfileReceipt.evidence.commands[0].commandSHA256)
    }

    @Test("Static evidence contains only coordinator-owned static facts")
    func evidenceExcludesUnobservedFields() throws {
        let snapshot = try validProfileSnapshot()
        let receipt = try coordinate(snapshot: snapshot, policySHA256: policySHA256)

        #expect(receipt.evidence.permissions == snapshot.profile.permissions)
        #expect(receipt.evidence.testCounts == nil)
        #expect(receipt.evidence.reviewRevision == nil)
        #expect(receipt.evidence.artifacts.isEmpty)
        #expect(receipt.evidence.residualRisks.isEmpty)
    }

    private func coordinate(
        snapshot: ProfileSnapshot,
        policySHA256: String,
        sourceRepository: String = "MArtem/example",
        sourceRevision: String = sourceRevision,
        engineRevision: String = engineRevision
    ) throws -> StaticEvidenceReceipt {
        try StaticEvidenceCoordinator.coordinate(
            observation: try observation(
                status: .pass,
                profileSHA256: snapshot.sha256,
                policySHA256: policySHA256
            ),
            context: context(
                profileSnapshot: snapshot,
                sourceRepository: sourceRepository,
                sourceRevision: sourceRevision,
                engineRevision: engineRevision,
                policySHA256: policySHA256
            )
        )
    }

    private func observation(
        status: QualityStatus,
        profileSHA256: String?,
        policySHA256: String?
    ) throws -> ValidatedStaticWorkerObservation {
        let report = QualityReport(
            command: "static",
            checks: [
                QualityCheck(
                    id: "QC.STATIC.SCAN",
                    status: status,
                    message: "Static worker result."
                )
            ]
        )
        let result = BoundedProcessResult(
            output: try JSONEncoder().encode(
                StaticWorkerResponse(
                    report: report,
                    profileSHA256: profileSHA256,
                    policySHA256: policySHA256
                )
            ),
            terminationStatus: terminationStatus(for: status),
            exitedNormally: true,
            timedOut: false,
            outputLimitExceeded: false,
            outputDrainCompleted: true
        )
        return try #require(StaticWorkerBoundary.validatedObservation(for: result))
    }

    private func context(
        profileSnapshot: ProfileSnapshot,
        sourceRepository: String = "MArtem/example",
        sourceRevision: String = sourceRevision,
        engineRevision: String = engineRevision,
        policySHA256: String = policySHA256,
        toolchain: EvidenceToolchain = toolchain
    ) -> StaticEvidenceObservedContext {
        StaticEvidenceObservedContext(
            sourceRepository: sourceRepository,
            sourceRevision: sourceRevision,
            engineRevision: engineRevision,
            toolchain: toolchain,
            profileSnapshot: profileSnapshot,
            policySHA256: policySHA256
        )
    }

    private func validProfileSnapshot() throws -> ProfileSnapshot {
        try ProfileSnapshot(data: Data(validProfileJSON.utf8))
    }

    private func terminationStatus(for status: QualityStatus) -> Int32 {
        switch status {
        case .pass:
            return 0
        case .fail:
            return 1
        case .blocked:
            return 2
        }
    }

    private var validProfileJSON: String {
        """
        {"schemaVersion":1,"project":{"kind":"xcodeproj","path":"App.xcodeproj"},"scheme":"App","sourcePaths":["Sources"],"mode":"controlled","permissions":{"testCreation":"allow","testModification":"allow","localTestExecution":"ask","githubExecution":"manual","uiTests":"deny","simulatorOrDevice":"deny","performanceOrInstruments":"deny"},"sandbox":{"root":"/sandbox","cache":"/sandbox/cache"}}
        """
    }
}

struct StaticEvidenceCase: Sendable {
    let status: QualityStatus
    let expectedGateStatus: GateStatus
    let expectedVerdict: AdvisoryVerdict
    let expectedExitCode: Int
}

enum MissingDigestCase: CaseIterable, Sendable {
    case profile
    case policy

    func observation(profileSHA256: String) throws -> ValidatedStaticWorkerObservation {
        let report: QualityReport
        let responseProfileSHA256: String?
        let responsePolicySHA256: String?
        switch self {
        case .profile:
            report = QualityReport(
                command: "static",
                checks: [QualityCheck(id: "QC.PROFILE.UNREADABLE", status: .fail, message: "Unreadable.")]
            )
            responseProfileSHA256 = nil
            responsePolicySHA256 = nil
        case .policy:
            report = QualityReport(
                command: "static",
                checks: [QualityCheck(id: "QC.POLICY.UNREADABLE", status: .fail, message: "Unreadable.")]
            )
            responseProfileSHA256 = profileSHA256
            responsePolicySHA256 = nil
        }
        let result = BoundedProcessResult(
            output: try JSONEncoder().encode(
                StaticWorkerResponse(
                    report: report,
                    profileSHA256: responseProfileSHA256,
                    policySHA256: responsePolicySHA256
                )
            ),
            terminationStatus: 1,
            exitedNormally: true,
            timedOut: false,
            outputLimitExceeded: false,
            outputDrainCompleted: true
        )
        return try #require(StaticWorkerBoundary.validatedObservation(for: result))
    }
}

enum InvalidContextCase: CaseIterable, Sendable {
    case emptyRepository
    case malformedSourceRevision
    case oversizedToolchain

    func context(profileSnapshot: ProfileSnapshot) -> StaticEvidenceObservedContext {
        switch self {
        case .emptyRepository:
            return StaticEvidenceObservedContext(
                sourceRepository: "",
                sourceRevision: sourceRevision,
                engineRevision: engineRevision,
                toolchain: toolchain,
                profileSnapshot: profileSnapshot,
                policySHA256: policySHA256
            )
        case .malformedSourceRevision:
            return StaticEvidenceObservedContext(
                sourceRepository: "MArtem/example",
                sourceRevision: "not-a-revision",
                engineRevision: engineRevision,
                toolchain: toolchain,
                profileSnapshot: profileSnapshot,
                policySHA256: policySHA256
            )
        case .oversizedToolchain:
            return StaticEvidenceObservedContext(
                sourceRepository: "MArtem/example",
                sourceRevision: sourceRevision,
                engineRevision: engineRevision,
                toolchain: EvidenceToolchain(
                    swiftVersion: String(repeating: "x", count: 1_025),
                    xcodeVersion: "Xcode 16"
                ),
                profileSnapshot: profileSnapshot,
                policySHA256: policySHA256
            )
        }
    }
}

private let sourceRevision = String(repeating: "a", count: 40)
private let engineRevision = String(repeating: "b", count: 40)
private let policySHA256 = String(repeating: "c", count: 64)
private let toolchain = EvidenceToolchain(swiftVersion: "Swift 6.0", xcodeVersion: "Xcode 16.0")
