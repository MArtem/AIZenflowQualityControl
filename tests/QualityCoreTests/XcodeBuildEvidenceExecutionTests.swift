import Foundation
import Testing
@testable import QualityCore

@Suite("Xcode build evidence public execution")
struct XcodeBuildEvidenceExecutionTests {
    @Test("A stable supervised build produces the only evidence-bearing PASS")
    func stableBuildProducesEvidence() throws {
        let initial = try context()
        let result = XcodeBuildEvidenceExecution.execute(
            initialContext: initial,
            selection: selection,
            runBuild: { _, _ in observation },
            observeFinalContext: { initial }
        )

        #expect(result.status == .pass)
        #expect(result.report.status == .pass)
        #expect(result.evidence?.claimedVerdict == .ready)
        #expect(result.verification?.verdict == .ready)
        #expect(result.verification?.issues.isEmpty == true)
    }

    @Test("Preflight rejection prevents build execution")
    func preflightRejectionPreventsBuild() throws {
        var didRunBuild = false
        let result = XcodeBuildEvidenceExecution.execute(
            initialContext: try context(userAuthorizedActions: []),
            selection: selection,
            runBuild: { _, _ in
                didRunBuild = true
                return observation
            },
            observeFinalContext: { nil }
        )

        #expect(result.status == .blocked)
        #expect(result.evidence == nil)
        #expect(result.verification == nil)
        #expect(!didRunBuild)
    }

    @Test("A failed build emits FAIL without evidence")
    func failedBuildHasNoEvidence() throws {
        let initial = try context()
        let result = XcodeBuildEvidenceExecution.execute(
            initialContext: initial,
            selection: selection,
            runBuild: { _, _ in
                throw XcodeBuildEvidenceSupervisionError.verification(.buildProcessFailed(1))
            },
            observeFinalContext: { initial }
        )

        #expect(result.status == .fail)
        #expect(result.report.status == .fail)
        #expect(result.evidence == nil)
        #expect(result.verification == nil)
    }

    @Test("Input mutation after build blocks evidence")
    func changedInputBlocksEvidence() throws {
        let initial = try context()
        let final = try context(sourceRevision: String(repeating: "f", count: 40))
        let result = XcodeBuildEvidenceExecution.execute(
            initialContext: initial,
            selection: selection,
            runBuild: { _, _ in observation },
            observeFinalContext: { final }
        )

        #expect(result.status == .blocked)
        #expect(result.evidence == nil)
        #expect(result.verification == nil)
    }

    @Test("An unverified PASS report is converted to BLOCKED")
    func unverifiedPassCannotEscape() {
        let result = XcodeBuildEvidenceExecutionResult(
            report: QualityReport(
                command: "build",
                checks: [
                    QualityCheck(
                        id: "QC.BUILD",
                        status: .pass,
                        message: "Caller asserted PASS without a receipt."
                    )
                ]
            )
        )

        #expect(result.status == .blocked)
        #expect(result.report.status == .blocked)
        #expect(result.evidence == nil)
        #expect(result.verification == nil)
    }

    @Test("Manual GitHub execution is accepted and off is blocked before build")
    func githubPolicyIsEnforced() throws {
        let local = try context()
        let localResult = XcodeBuildEvidenceExecution.execute(
            initialContext: local,
            selection: selection,
            runBuild: { _, _ in observation },
            observeFinalContext: { local }
        )
        let manual = try context(
            executionAction: .githubExecution,
            githubExecution: "manual"
        )
        let passing = XcodeBuildEvidenceExecution.execute(
            initialContext: manual,
            selection: selection,
            runBuild: { _, _ in observation },
            observeFinalContext: { manual }
        )
        var offDidRunBuild = false
        let blockedContext = try context(
            executionAction: .githubExecution,
            githubExecution: "off"
        )
        let blocked = XcodeBuildEvidenceExecution.execute(
            initialContext: blockedContext,
            selection: selection,
            runBuild: { _, _ in
                offDidRunBuild = true
                return observation
            },
            observeFinalContext: { blockedContext }
        )

        #expect(passing.status == .pass)
        #expect(passing.evidence?.commands.first?.actions == [.githubExecution])
        #expect(
            localResult.evidence?.commands.first?.commandSHA256
                != passing.evidence?.commands.first?.commandSHA256
        )
        #expect(blocked.status == .blocked)
        #expect(blocked.evidence == nil)
        #expect(!offDidRunBuild)
    }

    @Test("Published build result schema is valid JSON with the public command identity")
    func resultSchemaIsPublished() throws {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let schemaURL = repositoryRoot.appendingPathComponent(
            "schemas/build-evidence-result.schema.json"
        )
        let schema = try #require(
            try JSONSerialization.jsonObject(with: Data(contentsOf: schemaURL))
                as? [String: Any]
        )
        let properties = try #require(schema["properties"] as? [String: Any])
        let command = try #require(properties["command"] as? [String: Any])
        let alternatives = try #require(schema["oneOf"] as? [[String: Any]])

        #expect(schema["$schema"] as? String == "https://json-schema.org/draft/2020-12/schema")
        #expect(command["const"] as? String == "build-evidence")
        #expect(alternatives.count == 3)
    }

    private func context(
        sourceRevision: String = executionSourceRevision,
        executionAction: PermissionAction = .localBuildExecution,
        githubExecution: String = "manual",
        userAuthorizedActions: Set<PermissionAction>? = nil
    ) throws -> XcodeBuildEvidenceObservedContext {
        XcodeBuildEvidenceObservedContext(
            sourceRepository: "MArtem/example",
            sourceRevision: sourceRevision,
            engineVersion: XcodeBuildEvidenceCoordinator.engineVersion,
            engineRevision: executionEngineRevision,
            engineCodeDirectoryHash: String(repeating: "d", count: 40),
            toolchain: EvidenceToolchain(
                swiftVersion: "Swift 6.0",
                xcodeVersion: "Xcode 16.0"
            ),
            profileSnapshot: try profileSnapshot(githubExecution: githubExecution),
            executionAction: executionAction,
            userAuthorizedActions: userAuthorizedActions ?? [executionAction]
        )
    }

    private func profileSnapshot(githubExecution: String) throws -> ProfileSnapshot {
        try ProfileSnapshot(data: Data(
            """
            {"schemaVersion":2,"project":{"kind":"xcodeproj","path":"App.xcodeproj"},"sourcePaths":["Sources"],"mode":"controlled","permissions":{"testCreation":"ask","testModification":"ask","localTestExecution":"ask","githubExecution":"\(githubExecution)","uiTests":"ask","simulatorOrDevice":"ask","performanceOrInstruments":"ask"},"sandbox":{"root":".quality-control","cache":".quality-control/cache"},"engine":{"version":"\(XcodeBuildEvidenceCoordinator.engineVersion)","revision":"\(executionEngineRevision)"},"xcode":{"sourceMembership":{"authority":"xcode-build-graph"},"schemes":[{"name":"App","targets":["App"],"configurations":["Debug"],"destinations":["platform=macOS"],"testPlans":[]}]},"applicability":[{"capability":"tests","status":"applicable","reason":"Required.","owner":"Owner","revisitCondition":"Profile changes."},{"capability":"snapshotTests","status":"notApplicable","reason":"Absent.","owner":"Owner","revisitCondition":"Feature changes."},{"capability":"uiTests","status":"deferred","reason":"User controlled.","owner":"Owner","revisitCondition":"User approval."},{"capability":"archiveSigning","status":"notApplicable","reason":"No release.","owner":"Owner","revisitCondition":"Release starts."},{"capability":"featureFlags","status":"notApplicable","reason":"No rollout.","owner":"Owner","revisitCondition":"Rollout starts."},{"capability":"privacy","status":"applicable","reason":"Required.","owner":"Owner","revisitCondition":"Profile changes."},{"capability":"observability","status":"deferred","reason":"Not integrated.","owner":"Owner","revisitCondition":"Integration starts."},{"capability":"platformCapabilities","status":"notApplicable","reason":"Absent.","owner":"Owner","revisitCondition":"Capabilities change."}]}
            """.utf8
        ))
    }
}

private let executionSourceRevision = String(repeating: "a", count: 40)
private let executionEngineRevision = String(repeating: "b", count: 40)
private let selection = XcodeBuildSelection(
    scheme: "App",
    configuration: "Debug",
    destination: "platform=macOS"
)
private let observation = XcodeBuildSupervisionObservation(
    selection: selection,
    resultBundlePath: "/sandbox/cache/evidence/Build.xcresult",
    evidence: XcodeBuildEvidenceObservation(
        buildResultsSHA256: String(repeating: "c", count: 64),
        buildLogSHA256: String(repeating: "d", count: 64),
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
