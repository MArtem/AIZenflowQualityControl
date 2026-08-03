import Foundation
import Testing
@testable import QualityCore

@Suite("Evidence artifact hash worker boundary")
struct EvidenceArtifactHashWorkerBoundaryTests {
    @Test("An empty request needs no worker process")
    func emptyRequestNeedsNoWorker() throws {
        let artifacts = try EvidenceArtifactHashWorkerBoundary.hash(
            relativePaths: [],
            snapshotRoot: URL(fileURLWithPath: "/missing-root"),
            executableURL: URL(fileURLWithPath: "/missing-worker")
        )

        #expect(artifacts.isEmpty)
    }

    @Test("Callers cannot widen or invalidate the hard timeout")
    func timeoutConfigurationFailsClosed() {
        for timeout in [0, .infinity, EvidenceArtifactHashWorkerBoundary.hardTimeoutSeconds + 1] {
            expectError(.workerFailure) {
                try EvidenceArtifactHashWorkerBoundary.hash(
                    relativePaths: ["report.json"],
                    snapshotRoot: URL(fileURLWithPath: "/missing-root"),
                    executableURL: URL(fileURLWithPath: "/missing-worker"),
                    timeoutSeconds: timeout
                )
            }
        }
    }

    @Test("A non-local snapshot URL fails before worker launch")
    func rejectsNonLocalSnapshotURL() throws {
        let snapshotURL = try #require(URL(string: "https://example.test/snapshot"))

        expectError(.repositoryRootUnavailable) {
            try EvidenceArtifactHashWorkerBoundary.hash(
                relativePaths: ["report.json"],
                snapshotRoot: snapshotURL,
                executableURL: URL(fileURLWithPath: "/missing-worker")
            )
        }
    }

    @Test("Oversized worker arguments fail before process launch")
    func oversizedWorkerArgumentsFailBeforeLaunch() {
        let prefix = String(repeating: "😀", count: 1_022)
        let paths = (0..<EvidenceArtifactHasher.maximumArtifactCount).map {
            prefix + String(format: "%02d", $0)
        }

        expectError(.workerRequestTooLarge) {
            try EvidenceArtifactHashWorkerBoundary.hash(
                relativePaths: paths,
                snapshotRoot: URL(fileURLWithPath: "/snapshot"),
                executableURL: URL(fileURLWithPath: "/worker")
            )
        }
    }

    @Test("A hard worker timeout fails closed")
    func timeoutFailsClosed() {
        expectError(.deadlineExceeded) {
            try EvidenceArtifactHashWorkerBoundary.artifacts(
                for: result(timedOut: true),
                expectedPaths: ["report.json"]
            )
        }
    }

    @Test("Malformed or mismatched worker output fails closed")
    func malformedOutputFailsClosed() throws {
        expectError(.workerFailure) {
            try EvidenceArtifactHashWorkerBoundary.artifacts(
                for: result(output: Data("{}".utf8), terminationStatus: 0),
                expectedPaths: ["report.json"]
            )
        }

        let mismatched = try encoded(
            .success([
                EvidenceArtifact(
                    path: "other.json",
                    sha256: String(repeating: "a", count: 64)
                )
            ])
        )
        expectError(.workerFailure) {
            try EvidenceArtifactHashWorkerBoundary.artifacts(
                for: result(output: mismatched, terminationStatus: 0),
                expectedPaths: ["report.json"]
            )
        }

        for failure in [
            EvidenceArtifactHashWorkerResponse.failure(
                EvidenceArtifactHashingError(code: .tooManyArtifacts)
            ),
            EvidenceArtifactHashWorkerResponse.failure(
                EvidenceArtifactHashingError(
                    code: .artifactTooLarge,
                    path: "outside.json"
                )
            )
        ] {
            expectError(.workerFailure) {
                try EvidenceArtifactHashWorkerBoundary.artifacts(
                    for: result(
                        output: try encoded(failure),
                        terminationStatus: 1
                    ),
                    expectedPaths: ["report.json"]
                )
            }
        }
    }

    @Test("Worker success and hashing failures preserve their contracts")
    func preservesWorkerContracts() throws {
        let expectedArtifact = EvidenceArtifact(
            path: "report.json",
            sha256: String(repeating: "a", count: 64)
        )
        let artifacts = try EvidenceArtifactHashWorkerBoundary.artifacts(
            for: result(
                output: try encoded(.success([expectedArtifact])),
                terminationStatus: 0
            ),
            expectedPaths: ["report.json"]
        )
        #expect(artifacts.map(\.path) == ["report.json"])

        expectError(.artifactTooLarge) {
            try EvidenceArtifactHashWorkerBoundary.artifacts(
                for: result(
                    output: try encoded(
                        .failure(
                            EvidenceArtifactHashingError(
                                code: .artifactTooLarge,
                                path: "report.json"
                            )
                        )
                    ),
                    terminationStatus: 1
                ),
                expectedPaths: ["report.json"]
            )
        }

        expectError(.repositorySnapshotRequired) {
            try EvidenceArtifactHashWorkerBoundary.artifacts(
                for: result(
                    output: try encoded(
                        .failure(
                            EvidenceArtifactHashingError(
                                code: .repositorySnapshotRequired
                            )
                        )
                    ),
                    terminationStatus: 1
                ),
                expectedPaths: ["report.json"]
            )
        }
    }

    private func encoded(
        _ response: EvidenceArtifactHashWorkerResponse
    ) throws -> Data {
        try JSONEncoder().encode(response)
    }

    private func result(
        output: Data = Data(),
        terminationStatus: Int32? = nil,
        timedOut: Bool = false
    ) -> BoundedProcessResult {
        BoundedProcessResult(
            output: output,
            terminationStatus: terminationStatus,
            exitedNormally: terminationStatus != nil,
            timedOut: timedOut,
            outputLimitExceeded: false,
            outputDrainCompleted: true
        )
    }

    private func expectError(
        _ expectedCode: EvidenceArtifactHashingError.Code,
        operation: () throws -> [EvidenceArtifact]
    ) {
        do {
            _ = try operation()
            Issue.record("Expected worker boundary error \(expectedCode.rawValue).")
        } catch let error as EvidenceArtifactHashingError {
            #expect(error.code == expectedCode)
        } catch {
            Issue.record("Unexpected worker boundary error: \(error)")
        }
    }
}
