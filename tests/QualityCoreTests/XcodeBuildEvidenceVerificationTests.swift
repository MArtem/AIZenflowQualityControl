import Foundation
import Testing
@testable import QualityCore

@Suite("Xcode build evidence verification")
struct XcodeBuildEvidenceVerificationTests {
    @Test("A successful process, result, and compiler log produce one bound observation")
    func verifiesBoundBuildEvidence() throws {
        let observation = try XcodeBuildEvidenceVerifier.verify(
            processResult: successfulProcess,
            buildResultsData: try buildResults(
                warningCount: 1,
                warnings: [issue(message: "Review this warning.")]
            ),
            buildLogData: try buildLog(
                command: "/usr/bin/swiftc -frontend -c /repository/Sources/App.swift"
            ),
            repositoryRoot: repositoryRoot,
            sourcePaths: ["Sources"]
        )

        #expect(observation.actionTitle == "Build")
        #expect(observation.warningCount == 1)
        #expect(observation.analyzerWarningCount == 0)
        #expect(observation.compiledSourcePaths == ["Sources/App.swift"])
        #expect(observation.compilerSectionCount == 1)
        #expect(observation.buildResultsSHA256.count == 64)
        #expect(observation.buildLogSHA256.count == 64)
    }

    @Test("A nonzero xcodebuild exit is rejected before result parsing")
    func rejectsFailedBuildProcess() {
        expectError(.buildProcessFailed(1)) {
            try XcodeBuildEvidenceVerifier.verify(
                processResult: BoundedProcessResult(
                    output: Data(),
                    terminationStatus: 1,
                    exitedNormally: true,
                    timedOut: false,
                    outputLimitExceeded: false,
                    outputDrainCompleted: true
                ),
                buildResultsData: Data(),
                buildLogData: Data(),
                repositoryRoot: repositoryRoot,
                sourcePaths: ["Sources"]
            )
        }
    }

    @Test("An unsuccessful structured build result is rejected after a zero process exit")
    func rejectsUnsuccessfulBuildResult() throws {
        expectError(.unsuccessfulBuildResult) {
            try XcodeBuildEvidenceVerifier.verify(
                processResult: successfulProcess,
                buildResultsData: try buildResults(status: "failed"),
                buildLogData: try buildLog(
                    command: "/usr/bin/swiftc -frontend -c /repository/Sources/App.swift"
                ),
                repositoryRoot: repositoryRoot,
                sourcePaths: ["Sources"]
            )
        }
    }

    @Test("Inconsistent structured issue counts are rejected")
    func rejectsInconsistentIssueCounts() throws {
        expectError(.inconsistentIssueCounts) {
            try XcodeBuildEvidenceVerifier.verify(
                processResult: successfulProcess,
                buildResultsData: try buildResults(warningCount: 2),
                buildLogData: try buildLog(
                    command: "/usr/bin/swiftc -frontend -c /repository/Sources/App.swift"
                ),
                repositoryRoot: repositoryRoot,
                sourcePaths: ["Sources"]
            )
        }
    }

    @Test("A response-file source log remains blocked through the bound verifier")
    func propagatesBlockedSourceMembership() throws {
        expectError(.sourceMembership(.unresolvedCompilerInputList)) {
            try XcodeBuildEvidenceVerifier.verify(
                processResult: successfulProcess,
                buildResultsData: try buildResults(),
                buildLogData: try buildLog(
                    command: "/usr/bin/swiftc -frontend -c @/repository/Inputs.SwiftFileList"
                ),
                repositoryRoot: repositoryRoot,
                sourcePaths: ["Sources"]
            )
        }
    }

    @Test("Timed out process evidence is rejected before result parsing")
    func rejectsTimedOutBuildProcess() {
        expectError(.buildProcessTimedOut) {
            try XcodeBuildEvidenceVerifier.verify(
                processResult: BoundedProcessResult(
                    output: Data(),
                    terminationStatus: nil,
                    exitedNormally: false,
                    timedOut: true,
                    outputLimitExceeded: false,
                    outputDrainCompleted: true
                ),
                buildResultsData: Data(),
                buildLogData: Data(),
                repositoryRoot: repositoryRoot,
                sourcePaths: ["Sources"]
            )
        }
    }

    private var repositoryRoot: URL {
        URL(fileURLWithPath: "/repository", isDirectory: true)
    }

    private var successfulProcess: BoundedProcessResult {
        BoundedProcessResult(
            output: Data(),
            terminationStatus: 0,
            exitedNormally: true,
            timedOut: false,
            outputLimitExceeded: false,
            outputDrainCompleted: true
        )
    }

    private func buildResults(
        status: String = "succeeded",
        warningCount: Int? = 0,
        warnings: [[String: Any]] = []
    ) throws -> Data {
        var result: [String: Any] = [
            "actionTitle": "Build",
            "analyzerWarningCount": 0,
            "analyzerWarnings": [],
            "destination": [
                "architecture": "arm64",
                "deviceId": "device-id",
                "deviceName": "iPhone",
                "modelName": "iPhone",
                "osVersion": "18.0",
                "platform": "iOS"
            ],
            "endTime": 2.0,
            "errorCount": 0,
            "errors": [],
            "startTime": 1.0,
            "status": status,
            "warnings": warnings
        ]
        if let warningCount {
            result["warningCount"] = warningCount
        }
        return try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
    }

    private func buildLog(command: String) throws -> Data {
        try JSONSerialization.data(
            withJSONObject: [
                "commandInvocationDetails": ["commandDetails": command],
                "messages": [],
                "subsections": []
            ],
            options: [.sortedKeys]
        )
    }

    private func issue(message: String) -> [String: Any] {
        ["issueType": "warning", "message": message]
    }

    private func expectError(
        _ expected: XcodeBuildEvidenceVerificationError,
        operation: () throws -> XcodeBuildEvidenceObservation
    ) {
        do {
            _ = try operation()
            Issue.record("Expected XcodeBuildEvidenceVerificationError.\(expected)")
        } catch let error as XcodeBuildEvidenceVerificationError {
            #expect(error == expected)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }
}
