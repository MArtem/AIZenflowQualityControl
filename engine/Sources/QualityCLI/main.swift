import Darwin
import Foundation
import QualityCore

private enum CLIError: Error {
    case message(String)
}

private func parseOptions(
    _ arguments: ArraySlice<String>,
    allowed: Set<String>
) throws -> [String: String] {
    let values = Array(arguments)
    var options: [String: String] = [:]
    var index = 0

    while index < values.count {
        let key = values[index]
        guard allowed.contains(key) else {
            throw CLIError.message("Unsupported option: \(key)")
        }
        guard options[key] == nil else {
            throw CLIError.message("Duplicate option: \(key)")
        }
        guard index + 1 < values.count else {
            throw CLIError.message("Missing value for option: \(key)")
        }

        options[key] = values[index + 1]
        index += 2
    }

    return options
}

private func required(_ key: String, in options: [String: String]) throws -> String {
    guard let value = options[key], !value.isEmpty else {
        throw CLIError.message("Required option is missing: \(key)")
    }
    return value
}

private func fileURL(_ path: String) -> URL {
    let currentDirectory = URL(
        fileURLWithPath: FileManager.default.currentDirectoryPath,
        isDirectory: true
    )
    return URL(fileURLWithPath: path, relativeTo: currentDirectory).standardizedFileURL
}

private func emit(_ report: QualityReport) -> Never {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]

    if let data = try? encoder.encode(report),
       let output = String(data: data, encoding: .utf8) {
        print(output)
    } else {
        print(#"{"command":"internal","schemaVersion":1,"status":"BLOCKED"}"#)
    }

    switch report.status {
    case .pass:
        exit(0)
    case .fail:
        exit(1)
    case .blocked:
        exit(2)
    }
}

private func emitStaticEvidence(_ result: StaticEvidenceExecutionResult) -> Never {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    if let data = try? encoder.encode(result),
       data.count <= StaticWorkerBoundary.maximumOutputBytes + 64 * 1_024,
       let output = String(data: data, encoding: .utf8) {
        print(output)
    } else {
        print(#"{"command":"static-evidence","evidence":null,"report":{"checks":[{"id":"QC.STATIC_EVIDENCE.OUTPUT_FAILURE","message":"Static evidence output could not be encoded within its bounded envelope.","status":"BLOCKED"}],"command":"static","schemaVersion":1,"status":"BLOCKED"},"schemaVersion":1,"status":"BLOCKED","verification":null}"#)
    }

    switch result.status {
    case .pass:
        exit(0)
    case .fail:
        exit(1)
    case .blocked:
        exit(2)
    }
}

private func emitArtifactHashWorkerResponse(
    _ response: EvidenceArtifactHashWorkerResponse,
    exitCode: Int32
) -> Never {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    guard var data = try? encoder.encode(response) else {
        exit(2)
    }
    data.append(0x0A)
    FileHandle.standardOutput.write(data)
    exit(exitCode)
}

private func emitStaticWorkerResponse(_ response: StaticWorkerResponse) -> Never {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    guard var data = try? encoder.encode(response) else {
        exit(2)
    }
    data.append(0x0A)
    FileHandle.standardOutput.write(data)

    switch response.report.status {
    case .pass:
        exit(0)
    case .fail:
        exit(1)
    case .blocked:
        exit(2)
    }
}

private func parseArtifactWorkerOptions(
    _ arguments: ArraySlice<String>
) throws -> (snapshotRoot: String, artifacts: [String]) {
    let values = Array(arguments)
    guard values.count >= 2,
          values[0] == "--snapshot-root" else {
        throw CLIError.message("Artifact worker snapshot root is missing.")
    }

    let snapshotRoot = values[1]
    var artifacts: [String] = []
    var index = 2
    while index < values.count {
        guard values[index] == "--artifact", index + 1 < values.count else {
            throw CLIError.message("Artifact worker arguments are malformed.")
        }
        artifacts.append(values[index + 1])
        guard artifacts.count <= EvidenceArtifactHasher.maximumArtifactCount else {
            throw EvidenceArtifactHashingError(code: .tooManyArtifacts)
        }
        index += 2
    }
    return (snapshotRoot, artifacts)
}

private let staticWorkerEnvironmentKey = "AIZENFLOW_QUALITY_INTERNAL_STATIC_WORKER"
private let staticJobDeadlineEnvironmentKey = "QC_STATIC_JOB_DEADLINE_EPOCH_SECONDS"

private func trustedParentProcessIdentifier() -> pid_t? {
    guard let executableURL = Bundle.main.executableURL else {
        return nil
    }

    let parentProcessIdentifier = getppid()
    var buffer = [CChar](repeating: 0, count: 4_096)
    let pathLength = proc_pidpath(
        parentProcessIdentifier,
        &buffer,
        UInt32(buffer.count)
    )
    guard pathLength > 0 else {
        return nil
    }

    let parentExecutablePath = String(
        decoding: buffer.prefix(Int(pathLength)).map { UInt8(bitPattern: $0) },
        as: UTF8.self
    )
    let parentExecutableURL = URL(fileURLWithPath: parentExecutablePath)
        .resolvingSymlinksInPath()
        .standardizedFileURL
    guard parentExecutableURL == executableURL
        .resolvingSymlinksInPath()
        .standardizedFileURL else {
        return nil
    }
    return parentProcessIdentifier
}

private func runStaticWorker(
    profileURL: URL,
    policyURL: URL,
    repositoryRoot: URL,
    deadlineEpochSeconds: String? = nil
) -> QualityReport {
    runStaticWorkerExecution(
        profileURL: profileURL,
        policyURL: policyURL,
        repositoryRoot: repositoryRoot,
        deadlineEpochSeconds: deadlineEpochSeconds
    ).report
}

private struct StaticWorkerExecution {
    let report: QualityReport
    let observation: ValidatedStaticWorkerObservation?
}

private func runStaticWorkerExecution(
    profileURL: URL,
    policyURL: URL,
    repositoryRoot: URL,
    deadlineEpochSeconds: String? = nil
) -> StaticWorkerExecution {
    guard let executableURL = Bundle.main.executableURL else {
        return StaticWorkerExecution(
            report: QualityReport(command: "static", checks: [
                QualityCheck(id: "QC.STATIC.WORKER_FAILURE", status: .blocked, message: "Static worker executable could not be resolved.")
            ]),
            observation: nil
        )
    }

    let process = Process()
    process.executableURL = executableURL
    process.arguments = [
        "__static-worker",
        "--profile", profileURL.path,
        "--policy", policyURL.path,
        "--repository-root", repositoryRoot.path
    ]
    var environment = ProcessInfo.processInfo.environment
    environment[staticWorkerEnvironmentKey] = "1"
    if let deadlineEpochSeconds {
        environment[staticJobDeadlineEnvironmentKey] = deadlineEpochSeconds
    }
    process.environment = environment

    do {
        guard let timeoutSeconds = StaticWorkerBoundary.timeoutSeconds(
            deadlineEpochSeconds: environment[staticJobDeadlineEnvironmentKey],
            nowEpochSeconds: Date().timeIntervalSince1970
        ) else {
            return StaticWorkerExecution(
                report: StaticWorkerBoundary.deadlineBudgetFailure(),
                observation: nil
            )
        }
        let result = try BoundedProcessRunner.run(
            process,
            timeoutSeconds: timeoutSeconds,
            maximumOutputBytes: StaticWorkerBoundary.maximumOutputBytes
        )
        let observation = StaticWorkerBoundary.validatedObservation(for: result)
        return StaticWorkerExecution(
            report: observation?.report ?? StaticWorkerBoundary.report(for: result),
            observation: observation
        )
    } catch {
        return StaticWorkerExecution(
            report: QualityReport(command: "static", checks: [
                QualityCheck(id: "QC.STATIC.WORKER_FAILURE", status: .blocked, message: "Static worker could not be launched.")
            ]),
            observation: nil
        )
    }
}

private struct GitCheckoutObservation: Equatable {
    let root: URL
    let revision: String
    let origin: String
}

private let boundedSubprocessTimeout: TimeInterval = 5
private let boundedSubprocessOutputBytes = 64 * 1_024

private func boundedToolOutput(
    executable: String,
    arguments: [String],
    currentDirectoryURL: URL? = nil
) -> String? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.currentDirectoryURL = currentDirectoryURL
    var environment = ProcessInfo.processInfo.environment
    for key in [
        "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL"
    ] {
        environment.removeValue(forKey: key)
    }
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    process.environment = environment

    guard let result = try? BoundedProcessRunner.run(
        process,
        timeoutSeconds: boundedSubprocessTimeout,
        maximumOutputBytes: boundedSubprocessOutputBytes
    ), result.exitedNormally,
       result.terminationStatus == 0,
       !result.timedOut,
       !result.outputLimitExceeded,
       result.outputDrainCompleted,
       let output = String(data: result.output, encoding: .utf8) else {
        return nil
    }
    return output.trimmingCharacters(in: .whitespacesAndNewlines)
}

private func canonicalDirectory(_ url: URL) -> URL? {
    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory),
          isDirectory.boolValue else {
        return nil
    }
    return url.resolvingSymlinksInPath().standardizedFileURL
}

private func observedGitCheckout(at requestedRoot: URL) -> GitCheckoutObservation? {
    guard let root = canonicalDirectory(requestedRoot),
          let reportedRoot = boundedToolOutput(
            executable: "/usr/bin/git",
            arguments: ["-C", root.path, "rev-parse", "--show-toplevel"]
          ),
          URL(fileURLWithPath: reportedRoot).resolvingSymlinksInPath().standardizedFileURL == root,
          let revision = boundedToolOutput(
            executable: "/usr/bin/git",
            arguments: ["-C", root.path, "rev-parse", "HEAD"]
          ),
          isLowercaseHex(revision, count: 40),
          let origin = boundedToolOutput(
            executable: "/usr/bin/git",
            arguments: ["-C", root.path, "remote", "get-url", "origin"]
          ),
          boundedToolOutput(
            executable: "/usr/bin/git",
            arguments: ["-C", root.path, "status", "--porcelain=v1", "--untracked-files=all"]
          ) == "" else {
        return nil
    }
    return GitCheckoutObservation(root: root, revision: revision, origin: origin)
}

private func hasIgnoredSourceContent(root: URL, sourcePaths: [String]) -> Bool {
    guard !sourcePaths.isEmpty else {
        return true
    }
    return boundedToolOutput(
        executable: "/usr/bin/git",
        arguments: ["-C", root.path, "status", "--porcelain=v1", "--ignored=matching", "--"] + sourcePaths
    ) != ""
}

private func githubRepositoryIdentity(from remote: String) -> String? {
    let normalized = remote.trimmingCharacters(in: .whitespacesAndNewlines)
    let prefixes = ["https://github.com/", "git@github.com:", "ssh://git@github.com/"]
    guard let prefix = prefixes.first(where: { normalized.hasPrefix($0) }) else {
        return nil
    }
    let path = String(normalized.dropFirst(prefix.count))
    let identity = path.hasSuffix(".git") ? String(path.dropLast(4)) : path
    let parts = identity.split(separator: "/", omittingEmptySubsequences: false)
    guard parts.count == 2,
          parts.allSatisfy({ !$0.isEmpty && !$0.contains(" ") }) else {
        return nil
    }
    return identity
}

private func isLowercaseHex(_ value: String, count: Int) -> Bool {
    let bytes = value.utf8
    return bytes.count == count && bytes.allSatisfy {
        ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
    }
}

private func isDescendant(_ url: URL, of root: URL) -> Bool {
    let path = url.resolvingSymlinksInPath().standardizedFileURL.path
    let rootPath = root.resolvingSymlinksInPath().standardizedFileURL.path
    return path.hasPrefix(rootPath + "/")
}

private func staticEvidenceBlocked(_ id: String, _ message: String) -> StaticEvidenceExecutionResult {
    StaticEvidenceExecutionResult(
        report: QualityReport(
            command: "static",
            checks: [QualityCheck(id: id, status: .blocked, message: message)]
        )
    )
}

private func runStaticEvidence(
    profileURL: URL,
    policyURL: URL,
    sourceRoot: URL,
    engineRoot: URL,
    expectedSourceRepository: String,
    expectedSourceRevision: String,
    expectedEngineRevision: String
) -> StaticEvidenceExecutionResult {
    guard isLowercaseHex(expectedSourceRevision, count: 40),
          isLowercaseHex(expectedEngineRevision, count: 40) else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.INVALID_EXPECTED_REVISION", "Expected revisions must be lowercase 40-byte Git object IDs.")
    }
    let deadlineEpochSeconds = String(Date().timeIntervalSince1970 + StaticWorkerBoundary.hardTimeoutSeconds)
    let snapshots: StaticEvidenceInputSnapshots
    do {
        snapshots = try StaticEvidenceInputSnapshots.load(profileURL: profileURL, policyURL: policyURL)
    } catch {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.SNAPSHOT_UNAVAILABLE", "Profile or policy snapshot could not be read through the bounded input boundary.")
    }
    guard ProfileValidator.validate(snapshots.profileSnapshot.profile).isEmpty else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.INVALID_PROFILE", "The profile snapshot is not semantically valid for static evidence execution.")
    }
    guard let source = observedGitCheckout(at: sourceRoot),
          let engine = observedGitCheckout(at: engineRoot),
          githubRepositoryIdentity(from: source.origin) == expectedSourceRepository,
          githubRepositoryIdentity(from: engine.origin) == "MArtem/AIZenflowQualityControl",
          source.revision == expectedSourceRevision,
          engine.revision == expectedEngineRevision else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.CHECKOUT_UNTRUSTED", "Source or engine checkout identity, revision, root, or cleanliness could not be verified.")
    }
    guard !hasIgnoredSourceContent(root: source.root, sourcePaths: snapshots.profileSnapshot.profile.sourcePaths) else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.IGNORED_SOURCE", "Ignored content exists inside a configured source path.")
    }
    let canonicalPolicyURL = policyURL.resolvingSymlinksInPath().standardizedFileURL
    guard isDescendant(canonicalPolicyURL, of: engine.root) else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.POLICY_UNTRUSTED", "The static policy must be a Git-tracked regular file inside the verified engine checkout.")
    }
    let policyRelativePath = String(canonicalPolicyURL.path.dropFirst(engine.root.path.count + 1))
    guard
          boundedToolOutput(
            executable: "/usr/bin/git",
            arguments: ["-C", engine.root.path, "ls-files", "--error-unmatch", "--", policyRelativePath]
          ) != nil else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.POLICY_UNTRUSTED", "The static policy must be a Git-tracked regular file inside the verified engine checkout.")
    }
    guard let swiftVersion = boundedToolOutput(executable: "/usr/bin/xcrun", arguments: ["swift", "--version"]),
          let xcodeVersion = boundedToolOutput(executable: "/usr/bin/xcrun", arguments: ["xcodebuild", "-version"]),
          swiftVersion.unicodeScalars.count <= 1_024,
          xcodeVersion.unicodeScalars.count <= 1_024 else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.TOOLCHAIN_UNAVAILABLE", "The selected Swift or Xcode toolchain could not be observed within its bounded envelope.")
    }

    let worker = runStaticWorkerExecution(
        profileURL: profileURL,
        policyURL: policyURL,
        repositoryRoot: source.root,
        deadlineEpochSeconds: deadlineEpochSeconds
    )
    guard let observation = worker.observation else {
        // The public report remains useful on an unauthenticated worker failure, but it is not evidence.
        return StaticEvidenceExecutionResult(report: worker.report)
    }
    guard observation.profileSHA256 == snapshots.profileSnapshot.sha256,
          observation.policySHA256 == snapshots.policySHA256 else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.SNAPSHOT_MISMATCH", "Worker snapshot digests did not match the parent-observed profile and policy bytes.")
    }
    guard observedGitCheckout(at: source.root) == source,
          observedGitCheckout(at: engine.root) == engine,
          !hasIgnoredSourceContent(root: source.root, sourcePaths: snapshots.profileSnapshot.profile.sourcePaths) else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.CHECKOUT_CHANGED", "Source or engine checkout changed during static execution.")
    }
    do {
        return StaticEvidenceExecutionResult(
            receipt: try StaticEvidenceCoordinator.coordinate(
                observation: observation,
                context: StaticEvidenceObservedContext(
                    sourceRepository: expectedSourceRepository,
                    sourceRevision: source.revision,
                    engineRevision: engine.revision,
                    toolchain: EvidenceToolchain(swiftVersion: swiftVersion, xcodeVersion: xcodeVersion),
                    profileSnapshot: snapshots.profileSnapshot,
                    policySHA256: snapshots.policySHA256
                )
            )
        )
    } catch {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.VERIFICATION_FAILURE", "Observed static facts could not be converted into verified evidence.")
    }
}

let arguments = CommandLine.arguments
guard arguments.count >= 2 else {
    emit(
        QualityCommands.blockedUsage(
            command: "usage",
            message: "Expected doctor, validate-profile, validate-evidence-expectation, static, or static-evidence."
        )
    )
}

let command = arguments[1]

do {
    switch command {
    case "validate-profile":
        let options = try parseOptions(arguments.dropFirst(2), allowed: ["--profile"])
        let profile = try required("--profile", in: options)
        emit(QualityCommands.validateProfile(at: fileURL(profile)))

    case "validate-evidence-expectation":
        let options = try parseOptions(arguments.dropFirst(2), allowed: ["--expectation"])
        let expectation = try required("--expectation", in: options)
        emit(QualityCommands.validateEvidenceExpectation(at: fileURL(expectation)))

    case "doctor":
        let options = try parseOptions(
            arguments.dropFirst(2),
            allowed: ["--profile", "--repository-root"]
        )
        let profile = try required("--profile", in: options)
        let repositoryRoot = try required("--repository-root", in: options)
        emit(
            QualityCommands.doctor(
                profileURL: fileURL(profile),
                repositoryRoot: fileURL(repositoryRoot)
            )
        )

    case "static":
        let options = try parseOptions(
            arguments.dropFirst(2),
            allowed: ["--profile", "--policy", "--repository-root"]
        )
        let profile = try required("--profile", in: options)
        let policy = try required("--policy", in: options)
        let repositoryRoot = try required("--repository-root", in: options)
        emit(
            runStaticWorker(
                profileURL: fileURL(profile),
                policyURL: fileURL(policy),
                repositoryRoot: fileURL(repositoryRoot)
            )
        )

    case "static-evidence":
        let options = try parseOptions(
            arguments.dropFirst(2),
            allowed: [
                "--profile", "--policy", "--repository-root", "--engine-repository-root",
                "--source-repository", "--expected-source-revision", "--expected-engine-revision"
            ]
        )
        emitStaticEvidence(
            runStaticEvidence(
                profileURL: fileURL(try required("--profile", in: options)),
                policyURL: fileURL(try required("--policy", in: options)),
                sourceRoot: fileURL(try required("--repository-root", in: options)),
                engineRoot: fileURL(try required("--engine-repository-root", in: options)),
                expectedSourceRepository: try required("--source-repository", in: options),
                expectedSourceRevision: try required("--expected-source-revision", in: options),
                expectedEngineRevision: try required("--expected-engine-revision", in: options)
            )
        )

    case "__static-worker":
        guard ProcessInfo.processInfo.environment[staticWorkerEnvironmentKey] == "1",
              let parentProcessIdentifier = trustedParentProcessIdentifier() else {
            emit(
                QualityCommands.blockedUsage(
                    command: "static",
                    message: "The internal static worker cannot be invoked directly."
                )
            )
        }
        let parentExitMonitor = ProcessExitMonitor(
            processIdentifier: parentProcessIdentifier
        ) {
            Darwin._exit(2)
        }
        guard getppid() == parentProcessIdentifier else {
            Darwin._exit(2)
        }
        let options = try parseOptions(
            arguments.dropFirst(2),
            allowed: ["--profile", "--policy", "--repository-root"]
        )
        let profile = try required("--profile", in: options)
        let policy = try required("--policy", in: options)
        let repositoryRoot = try required("--repository-root", in: options)
        let response = QualityCommands.staticWorkerResponse(
            profileURL: fileURL(profile),
            policyURL: fileURL(policy),
            repositoryRoot: fileURL(repositoryRoot)
        )
        withExtendedLifetime(parentExitMonitor) {
            emitStaticWorkerResponse(response)
        }

    case "__artifact-hash-worker":
        guard ProcessInfo.processInfo.environment[
            EvidenceArtifactHashWorkerBoundary.workerEnvironmentKey
        ] == "1",
        let parentProcessIdentifier = trustedParentProcessIdentifier() else {
            emitArtifactHashWorkerResponse(
                .failure(EvidenceArtifactHashingError(code: .workerFailure)),
                exitCode: 2
            )
        }
        let parentExitMonitor = ProcessExitMonitor(
            processIdentifier: parentProcessIdentifier
        ) {
            Darwin._exit(2)
        }
        guard getppid() == parentProcessIdentifier else {
            Darwin._exit(2)
        }
        do {
            let options = try parseArtifactWorkerOptions(arguments.dropFirst(2))
            let artifacts = try EvidenceArtifactHasher.hashSnapshotInWorker(
                relativePaths: options.artifacts,
                repositoryRoot: fileURL(options.snapshotRoot)
            )
            withExtendedLifetime(parentExitMonitor) {
                emitArtifactHashWorkerResponse(.success(artifacts), exitCode: 0)
            }
        } catch let error as EvidenceArtifactHashingError {
            withExtendedLifetime(parentExitMonitor) {
                emitArtifactHashWorkerResponse(.failure(error), exitCode: 1)
            }
        } catch {
            withExtendedLifetime(parentExitMonitor) {
                emitArtifactHashWorkerResponse(
                    .failure(EvidenceArtifactHashingError(code: .workerFailure)),
                    exitCode: 2
                )
            }
        }

    default:
        emit(
            QualityCommands.blockedUsage(
                command: command,
                message: "Unknown command. Expected doctor, validate-profile, validate-evidence-expectation, static, or static-evidence."
            )
        )
    }
} catch let CLIError.message(message) {
    emit(QualityCommands.blockedUsage(command: command, message: message))
} catch {
    emit(
        QualityCommands.blockedUsage(
            command: command,
            message: "Command arguments could not be processed."
        )
    )
}
