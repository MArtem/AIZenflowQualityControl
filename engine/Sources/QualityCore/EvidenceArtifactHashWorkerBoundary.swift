import Foundation

package struct EvidenceArtifactHashWorkerResponse: Codable, Sendable {
    package let artifacts: [EvidenceArtifact]?
    package let errorCode: EvidenceArtifactHashingError.Code?
    package let errorPath: String?

    package static func success(
        _ artifacts: [EvidenceArtifact]
    ) -> EvidenceArtifactHashWorkerResponse {
        EvidenceArtifactHashWorkerResponse(
            artifacts: artifacts,
            errorCode: nil,
            errorPath: nil
        )
    }

    package static func failure(
        _ error: EvidenceArtifactHashingError
    ) -> EvidenceArtifactHashWorkerResponse {
        EvidenceArtifactHashWorkerResponse(
            artifacts: nil,
            errorCode: error.code,
            errorPath: error.path
        )
    }
}

package enum EvidenceArtifactHashWorkerBoundary {
    package static let hardTimeoutSeconds = 30.0
    package static let maximumOutputBytes = 512 * 1_024
    package static let workerEnvironmentKey =
        "AIZENFLOW_QUALITY_INTERNAL_ARTIFACT_HASH_WORKER"

    package static func hash(
        relativePaths: [String],
        repositoryRoot: URL,
        executableURL: URL,
        timeoutSeconds: TimeInterval = hardTimeoutSeconds
    ) throws -> [EvidenceArtifact] {
        guard timeoutSeconds.isFinite,
              timeoutSeconds > 0,
              timeoutSeconds <= hardTimeoutSeconds else {
            throw EvidenceArtifactHashingError(code: .workerFailure)
        }
        let validatedPaths = try EvidenceArtifactHasher.validate(
            relativePaths: relativePaths
        )
        let expectedPaths = validatedPaths.map(\.0).sorted()
        guard !expectedPaths.isEmpty else {
            return []
        }

        let process = Process()
        process.executableURL = executableURL
        process.arguments = [
            "__artifact-hash-worker",
            "--repository-root", repositoryRoot.path
        ] + expectedPaths.flatMap { ["--artifact", $0] }
        var environment = ProcessInfo.processInfo.environment
        environment[workerEnvironmentKey] = "1"
        process.environment = environment

        let result: BoundedProcessResult
        do {
            result = try BoundedProcessRunner.run(
                process,
                timeoutSeconds: timeoutSeconds,
                maximumOutputBytes: maximumOutputBytes
            )
        } catch {
            throw EvidenceArtifactHashingError(code: .workerFailure)
        }
        return try artifacts(for: result, expectedPaths: expectedPaths)
    }

    package static func artifacts(
        for result: BoundedProcessResult,
        expectedPaths: [String]
    ) throws -> [EvidenceArtifact] {
        if result.timedOut {
            throw EvidenceArtifactHashingError(code: .deadlineExceeded)
        }
        guard result.outputDrainCompleted,
              !result.outputLimitExceeded,
              result.exitedNormally,
              let terminationStatus = result.terminationStatus,
              let response = try? JSONDecoder().decode(
                  EvidenceArtifactHashWorkerResponse.self,
                  from: result.output
              ) else {
            throw EvidenceArtifactHashingError(code: .workerFailure)
        }

        if terminationStatus == 1,
           response.artifacts == nil,
           let errorCode = response.errorCode,
           isExpectedWorkerFailure(
               errorCode,
               path: response.errorPath,
               expectedPaths: expectedPaths
           ) {
            throw EvidenceArtifactHashingError(
                code: errorCode,
                path: response.errorPath
            )
        }

        guard terminationStatus == 0,
              response.errorCode == nil,
              response.errorPath == nil,
              let artifacts = response.artifacts,
              artifacts.map(\.path) == expectedPaths,
              artifacts.allSatisfy({ isLowercaseSHA256($0.sha256) }) else {
            throw EvidenceArtifactHashingError(code: .workerFailure)
        }
        return artifacts
    }

    private static func isExpectedWorkerFailure(
        _ code: EvidenceArtifactHashingError.Code,
        path: String?,
        expectedPaths: [String]
    ) -> Bool {
        switch code {
        case .repositoryRootUnavailable:
            return path == nil
        case .artifactChangedDuringRead:
            return path == nil || (path.map(expectedPaths.contains) ?? false)
        case .artifactUnavailable,
             .artifactNotRegularFile,
             .artifactTooLarge,
             .artifactReadFailure:
            return path.map(expectedPaths.contains) ?? false
        case .tooManyArtifacts,
             .duplicatePath,
             .invalidPath,
             .deadlineExceeded,
             .workerFailure:
            return false
        }
    }

    private static func isLowercaseSHA256(_ value: String) -> Bool {
        let bytes = value.utf8
        guard bytes.count == 64 else {
            return false
        }
        return bytes.allSatisfy {
            (0x30...0x39).contains($0) || (0x61...0x66).contains($0)
        }
    }
}
