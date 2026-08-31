import Foundation
import Testing
@testable import QualityCore

@Suite("Xcode build evidence coordination")
struct XcodeBuildEvidenceCoordinatorTests {
    @Test("Authenticated build facts produce exact-input READY evidence")
    func authenticatedBuildProducesReadyEvidence() throws {
        let receipt = try coordinate()

        #expect(receipt.verification.verdict == .ready)
        #expect(receipt.verification.issues.isEmpty)
        #expect(receipt.evidence.profileSchemaVersion == 2)
        #expect(receipt.evidence.commands.count == 1)
        #expect(receipt.evidence.commands[0].actions == [.localBuildExecution])
        #expect(receipt.evidence.commands[0].authorization == .user)
        #expect(receipt.evidence.gates[0].id == "QC.BUILD")
        #expect(receipt.evidence.gates[0].status == .pass)
        #expect(receipt.evidence.artifacts.map(\.path) == [
            "xcode/build-results.json",
            "xcode/build-log.json"
        ])
        #expect(receipt.evidence.artifacts.map(\.sha256) == [buildResultsHash, buildLogHash])
    }

    @Test("Local build evidence requires explicit user authorization")
    func missingBuildAuthorizationFailsClosed() throws {
        expectError(.missingBuildAuthorization) {
            try XcodeBuildEvidenceCoordinator.coordinate(
                observation: observation(),
                context: try context(userAuthorizedActions: [])
            )
        }
    }

    @Test("The observed engine must match the profile pin")
    func mismatchedEnginePinFailsClosed() throws {
        expectError(.enginePinMismatch) {
            try XcodeBuildEvidenceCoordinator.coordinate(
                observation: observation(),
                context: try context(engineRevision: String(repeating: "e", count: 40))
            )
        }
    }

    @Test("Malformed trusted identity cannot produce evidence")
    func malformedIdentityFailsClosed() throws {
        expectError(.invalidTrustedContext) {
            try XcodeBuildEvidenceCoordinator.coordinate(
                observation: observation(),
                context: try context(sourceRevision: "not-a-revision")
            )
        }
    }

    @Test("Command identity and artifact set bind independent inputs")
    func commandAndArtifactsBindInputs() throws {
        let base = try coordinate()
        let changedSource = try coordinate(
            context: context(sourceRevision: String(repeating: "f", count: 40))
        )
        let changedToolchain = try coordinate(
            context: context(
                toolchain: EvidenceToolchain(
                    swiftVersion: "Swift 6.1",
                    xcodeVersion: "Xcode 16.0"
                )
            )
        )
        let differentlyPartitionedToolchain = try coordinate(
            context: context(
                toolchain: EvidenceToolchain(
                    swiftVersion: "Swift 6.1\nXcode",
                    xcodeVersion: "16.0"
                )
            )
        )
        let changedSelection = try coordinate(
            observation: observation(configuration: "Release"),
            profileSnapshot: profileSnapshot(configurations: ["Debug", "Release"])
        )
        let changedResults = try coordinate(
            observation: observation(buildResultsSHA256: String(repeating: "9", count: 64))
        )

        let baseCommandHash = base.evidence.commands[0].commandSHA256
        #expect(baseCommandHash != changedSource.evidence.commands[0].commandSHA256)
        #expect(baseCommandHash != changedToolchain.evidence.commands[0].commandSHA256)
        #expect(
            changedToolchain.evidence.commands[0].commandSHA256
                != differentlyPartitionedToolchain.evidence.commands[0].commandSHA256
        )
        #expect(baseCommandHash != changedSelection.evidence.commands[0].commandSHA256)
        #expect(baseCommandHash == changedResults.evidence.commands[0].commandSHA256)
        #expect(base.evidence.artifacts[0].sha256 != changedResults.evidence.artifacts[0].sha256)
    }

    private func coordinate(
        observation suppliedObservation: XcodeBuildSupervisionObservation? = nil,
        profileSnapshot: ProfileSnapshot? = nil,
        context suppliedContext: XcodeBuildEvidenceObservedContext? = nil
    ) throws -> XcodeBuildEvidenceReceipt {
        let snapshot = try profileSnapshot ?? self.profileSnapshot()
        return try XcodeBuildEvidenceCoordinator.coordinate(
            observation: suppliedObservation ?? observation(),
            context: suppliedContext ?? context(profileSnapshot: snapshot)
        )
    }

    private func context(
        profileSnapshot: ProfileSnapshot? = nil,
        sourceRevision: String = sourceRevision,
        engineRevision: String = engineRevision,
        toolchain: EvidenceToolchain = toolchain,
        userAuthorizedActions: Set<PermissionAction> = [.localBuildExecution]
    ) throws -> XcodeBuildEvidenceObservedContext {
        XcodeBuildEvidenceObservedContext(
            sourceRepository: "MArtem/example",
            sourceRevision: sourceRevision,
            engineVersion: "0.1.0-dev",
            engineRevision: engineRevision,
            engineCodeDirectoryHash: String(repeating: "d", count: 40),
            toolchain: toolchain,
            profileSnapshot: try profileSnapshot ?? self.profileSnapshot(),
            userAuthorizedActions: userAuthorizedActions
        )
    }

    private func observation(
        configuration: String = "Debug",
        buildResultsSHA256: String = buildResultsHash
    ) -> XcodeBuildSupervisionObservation {
        XcodeBuildSupervisionObservation(
            selection: XcodeBuildSelection(
                scheme: "App",
                configuration: configuration,
                destination: "platform=macOS"
            ),
            resultBundlePath: "/sandbox/cache/evidence/Build.xcresult",
            evidence: XcodeBuildEvidenceObservation(
                buildResultsSHA256: buildResultsSHA256,
                buildLogSHA256: buildLogHash,
                actionTitle: "Build",
                destination: XcodeBuildDestinationObservation(
                    deviceID: "device-id",
                    deviceName: "Mac",
                    architecture: "arm64",
                    modelName: "Mac",
                    platform: "macOS",
                    osVersion: "15.0",
                    osBuildNumber: nil
                ),
                startTime: 1,
                endTime: 2,
                warningCount: 0,
                analyzerWarningCount: 0,
                compiledSourcePaths: ["Sources/App.swift"],
                compilerSectionCount: 1
            )
        )
    }

    private func profileSnapshot(
        configurations: [String] = ["Debug"]
    ) throws -> ProfileSnapshot {
        let configurationJSON = configurations.map { "\"\($0)\"" }.joined(separator: ",")
        return try ProfileSnapshot(data: Data(
            """
            {"schemaVersion":2,"project":{"kind":"xcodeproj","path":"App.xcodeproj"},"sourcePaths":["Sources"],"mode":"controlled","permissions":{"testCreation":"ask","testModification":"ask","localTestExecution":"ask","githubExecution":"manual","uiTests":"ask","simulatorOrDevice":"ask","performanceOrInstruments":"ask"},"sandbox":{"root":".quality-control","cache":".quality-control/cache"},"engine":{"version":"0.1.0-dev","revision":"\(engineRevision)"},"xcode":{"sourceMembership":{"authority":"xcode-build-graph"},"schemes":[{"name":"App","targets":["App"],"configurations":[\(configurationJSON)],"destinations":["platform=macOS"],"testPlans":[]}]},"applicability":[{"capability":"tests","status":"applicable","reason":"Required.","owner":"Owner","revisitCondition":"Profile changes."},{"capability":"snapshotTests","status":"notApplicable","reason":"Absent.","owner":"Owner","revisitCondition":"Feature changes."},{"capability":"uiTests","status":"deferred","reason":"User controlled.","owner":"Owner","revisitCondition":"User approval."},{"capability":"archiveSigning","status":"notApplicable","reason":"No release.","owner":"Owner","revisitCondition":"Release starts."},{"capability":"featureFlags","status":"notApplicable","reason":"No rollout.","owner":"Owner","revisitCondition":"Rollout starts."},{"capability":"privacy","status":"applicable","reason":"Required.","owner":"Owner","revisitCondition":"Profile changes."},{"capability":"observability","status":"deferred","reason":"Not integrated.","owner":"Owner","revisitCondition":"Integration starts."},{"capability":"platformCapabilities","status":"notApplicable","reason":"Absent.","owner":"Owner","revisitCondition":"Capabilities change."}]}
            """.utf8
        ))
    }

    private func expectError(
        _ expected: XcodeBuildEvidenceCoordinationError,
        operation: () throws -> XcodeBuildEvidenceReceipt
    ) {
        do {
            _ = try operation()
            Issue.record("Expected XcodeBuildEvidenceCoordinationError.\(expected)")
        } catch let error as XcodeBuildEvidenceCoordinationError {
            #expect(error == expected)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }
}

private let sourceRevision = String(repeating: "a", count: 40)
private let engineRevision = String(repeating: "b", count: 40)
private let buildResultsHash = String(repeating: "c", count: 64)
private let buildLogHash = String(repeating: "d", count: 64)
private let toolchain = EvidenceToolchain(
    swiftVersion: "Swift 6.0",
    xcodeVersion: "Xcode 16.0"
)
