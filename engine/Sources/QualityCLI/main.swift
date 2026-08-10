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

private func boundedFileData(at url: URL, maximumBytes: Int) throws -> Data {
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    var data = Data()
    while let chunk = try handle.read(upToCount: min(64 * 1_024, maximumBytes + 1 - data.count)),
          !chunk.isEmpty {
        guard data.count + chunk.count <= maximumBytes else {
            throw CLIError.message("Internal worker input exceeded its immutable byte limit.")
        }
        data.append(chunk)
    }
    return data
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
        exit(2)
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
    manifestURL: URL? = nil,
    expectedWorkerCodeDirectoryHash: String? = nil,
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
    if let manifestURL {
        process.arguments! += ["--manifest", manifestURL.path]
    }
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
            maximumOutputBytes: StaticWorkerBoundary.maximumOutputBytes,
            validateLaunchedProcess: { processIdentifier in
                guard let expectedWorkerCodeDirectoryHash else {
                    return true
                }
                return ProcessCodeIdentity.codeDirectoryHash(
                    forProcessIdentifier: processIdentifier
                ) == expectedWorkerCodeDirectoryHash
            }
        )
        let observation = StaticWorkerBoundary.validatedObservation(for: result)
        return StaticWorkerExecution(
            report: observation?.report ?? StaticWorkerBoundary.report(for: result),
            observation: observation
        )
    } catch BoundedProcessRunnerError.identityRejected {
        return StaticWorkerExecution(
            report: QualityReport(command: "static", checks: [
                QualityCheck(id: "QC.STATIC.WORKER_IDENTITY", status: .blocked, message: "Static worker code identity did not match the authenticated parent executable.")
            ]),
            observation: nil
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
    currentDirectoryURL: URL? = nil,
    maximumOutputBytes: Int = boundedSubprocessOutputBytes
) -> String? {
    guard let data = boundedToolData(
        executable: executable,
        arguments: arguments,
        currentDirectoryURL: currentDirectoryURL,
        maximumOutputBytes: maximumOutputBytes
    ), let output = String(data: data, encoding: .utf8) else {
        return nil
    }
    return output.trimmingCharacters(in: .whitespacesAndNewlines)
}

private func boundedToolData(
    executable: String,
    arguments: [String],
    currentDirectoryURL: URL? = nil,
    maximumOutputBytes: Int = boundedSubprocessOutputBytes
) -> Data? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.currentDirectoryURL = currentDirectoryURL
    var environment = ProcessInfo.processInfo.environment
    for key in [
        "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM", "GIT_CONFIG_PARAMETERS", "GIT_ATTR_NOSYSTEM"
    ] {
        environment.removeValue(forKey: key)
    }
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = "/dev/null"
    environment["GIT_CONFIG_SYSTEM"] = "/dev/null"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    process.environment = environment

    guard let result = try? BoundedProcessRunner.run(
        process,
        timeoutSeconds: boundedSubprocessTimeout,
        maximumOutputBytes: maximumOutputBytes
    ), result.exitedNormally,
       result.terminationStatus == 0,
       !result.timedOut,
       !result.outputLimitExceeded,
       result.outputDrainCompleted else {
        return nil
    }
    return result.output
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
          let origin = rawOriginURL(at: root),
          boundedToolOutput(
            executable: "/usr/bin/git",
            arguments: ["-C", root.path, "status", "--porcelain=v1", "--untracked-files=all"]
          ) == "" else {
        return nil
    }
    return GitCheckoutObservation(root: root, revision: revision, origin: origin)
}

private func rawOriginURL(at root: URL) -> String? {
    guard let data = boundedToolData(
        executable: "/usr/bin/git",
        arguments: ["-C", root.path, "config", "--local", "--no-includes", "--get-all", "remote.origin.url"]
    ), let output = String(data: data, encoding: .utf8) else {
        return nil
    }
    let values = output.split(separator: "\n", omittingEmptySubsequences: false)
    guard values.count == 2,
          !values[0].isEmpty,
          !values[0].contains(where: { $0.isWhitespace }) else {
        return nil
    }
    return String(values[0])
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
    snapshotRoot: URL,
    expectedSourceRepository: String,
    expectedSourceRevision: String,
    expectedEngineRevision: String,
    expectedEngineCodeDirectoryHash: String
) -> StaticEvidenceExecutionResult {
    guard isLowercaseHex(expectedSourceRevision, count: 40),
          isLowercaseHex(expectedEngineRevision, count: 40),
          isLowercaseHex(expectedEngineCodeDirectoryHash, count: 40) else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.INVALID_EXPECTED_IDENTITY", "Expected revisions and engine CodeDirectory hash must be lowercase 40-byte hexadecimal values.")
    }
    guard ProcessCodeIdentity.currentCodeDirectoryHash() == expectedEngineCodeDirectoryHash else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.EXECUTABLE_UNTRUSTED", "The running executable code identity did not match the caller-trusted engine CodeDirectory hash.")
    }
    let deadlineEpochSeconds = StaticWorkerBoundary.boundedDeadlineEpochSeconds(
        inheritedDeadlineEpochSeconds: ProcessInfo.processInfo.environment[staticJobDeadlineEnvironmentKey],
        nowEpochSeconds: Date().timeIntervalSince1970
    )
    guard let source = observedGitCheckout(at: sourceRoot),
          let engine = observedGitCheckout(at: engineRoot),
          githubRepositoryIdentity(from: source.origin) == expectedSourceRepository,
          githubRepositoryIdentity(from: engine.origin) == "MArtem/AIZenflowQualityControl",
          source.revision == expectedSourceRevision,
          engine.revision == expectedEngineRevision else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.CHECKOUT_UNTRUSTED", "Source or engine checkout identity, revision, root, or cleanliness could not be verified.")
    }
    let canonicalPolicyURL = policyURL.resolvingSymlinksInPath().standardizedFileURL
    guard isDescendant(canonicalPolicyURL, of: engine.root) else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.POLICY_UNTRUSTED", "The static policy must be a Git-tracked regular file inside the verified engine checkout.")
    }
    let policyRelativePath = String(canonicalPolicyURL.path.dropFirst(engine.root.path.count + 1))
    guard let policyData = boundedToolData(
            executable: "/usr/bin/git",
            arguments: ["-C", engine.root.path, "show", "\(engine.revision):\(policyRelativePath)"],
            maximumOutputBytes: StaticEvidenceInputSnapshots.maximumInputBytes
          ) else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.POLICY_UNTRUSTED", "The static policy must be a Git-tracked regular file inside the verified engine checkout.")
    }
    let snapshots: StaticEvidenceInputSnapshots
    do {
        snapshots = try StaticEvidenceInputSnapshots.load(profileURL: profileURL, policyData: policyData)
    } catch {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.SNAPSHOT_UNAVAILABLE", "Profile or policy snapshot could not be read through the bounded input boundary.")
    }
    guard ProfileValidator.validate(snapshots.profileSnapshot.profile).isEmpty else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.INVALID_PROFILE", "The profile snapshot is not semantically valid for static evidence execution.")
    }
    guard let manifest = boundedToolData(
        executable: "/usr/bin/git",
        arguments: ["-C", source.root.path, "ls-tree", "-r", "-z", "-l", "--full-tree", source.revision, "--"] + snapshots.profileSnapshot.profile.sourcePaths.map { ":(literal)\($0)" },
        maximumOutputBytes: GitTreeStaticSnapshot.maximumManifestBytes
    ) else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.SOURCE_TREE_UNAVAILABLE", "The exact source Git tree could not be observed within its bounded envelope.")
    }
    let sourceSnapshot: GitTreeStaticSnapshot
    do {
        sourceSnapshot = try GitTreeStaticSnapshot(manifest: manifest)
    } catch {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.SOURCE_TREE_INVALID", "The exact source Git tree manifest was malformed or exceeded its immutable limits.")
    }
    guard let swiftVersion = boundedToolOutput(executable: "/usr/bin/xcrun", arguments: ["swift", "--version"]),
          let xcodeVersion = boundedToolOutput(executable: "/usr/bin/xcrun", arguments: ["xcodebuild", "-version"]),
          swiftVersion.unicodeScalars.count <= 1_024,
          xcodeVersion.unicodeScalars.count <= 1_024 else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.TOOLCHAIN_UNAVAILABLE", "The selected Swift or Xcode toolchain could not be observed within its bounded envelope.")
    }

    var inputDirectory: URL?
    do {
        inputDirectory = snapshotRoot.appendingPathComponent(
            "static-evidence-input-" + UUID().uuidString,
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: inputDirectory!, withIntermediateDirectories: false)
        try snapshots.profileData.write(
            to: inputDirectory!.appendingPathComponent("profile.json"),
            options: .atomic
        )
        try snapshots.policyData.write(
            to: inputDirectory!.appendingPathComponent("policy.json"),
            options: .atomic
        )
        try manifest.write(
            to: inputDirectory!.appendingPathComponent("source-manifest.bin"),
            options: .atomic
        )
    } catch {
        if let inputDirectory { try? FileManager.default.removeItem(at: inputDirectory) }
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.SOURCE_SNAPSHOT_UNAVAILABLE", "The exact source Git tree could not be materialized as a private read-only scan view.")
    }
    guard let inputDirectory else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.SOURCE_SNAPSHOT_UNAVAILABLE", "The exact source Git tree could not be prepared for the worker.")
    }
    defer { try? FileManager.default.removeItem(at: inputDirectory) }
    let worker = runStaticWorkerExecution(
        profileURL: inputDirectory.appendingPathComponent("profile.json"),
        policyURL: inputDirectory.appendingPathComponent("policy.json"),
        repositoryRoot: source.root,
        manifestURL: inputDirectory.appendingPathComponent("source-manifest.bin"),
        expectedWorkerCodeDirectoryHash: expectedEngineCodeDirectoryHash,
        deadlineEpochSeconds: deadlineEpochSeconds
    )
    guard let observation = worker.observation else {
        // The public report remains useful on an unauthenticated worker failure, but it is not evidence.
        return StaticEvidenceExecutionResult(report: worker.report)
    }
    guard observation.profileSHA256 == snapshots.profileSnapshot.sha256,
          observation.policySHA256 == snapshots.policySHA256,
          observation.sourceManifestSHA256 == sourceSnapshot.sha256 else {
        return staticEvidenceBlocked("QC.STATIC_EVIDENCE.SNAPSHOT_MISMATCH", "Worker snapshot digests did not match the parent-observed profile and policy bytes.")
    }
    guard observedGitCheckout(at: source.root) == source,
          observedGitCheckout(at: engine.root) == engine else {
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
                    engineCodeDirectoryHash: expectedEngineCodeDirectoryHash,
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
        do {
            let options = try parseOptions(
                arguments.dropFirst(2),
                allowed: [
                    "--profile", "--policy", "--repository-root", "--engine-repository-root",
                    "--snapshot-root", "--source-repository", "--expected-source-revision", "--expected-engine-revision", "--expected-engine-cdhash"
                ]
            )
            emitStaticEvidence(
                runStaticEvidence(
                    profileURL: fileURL(try required("--profile", in: options)),
                    policyURL: fileURL(try required("--policy", in: options)),
                    sourceRoot: fileURL(try required("--repository-root", in: options)),
                    engineRoot: fileURL(try required("--engine-repository-root", in: options)),
                    snapshotRoot: fileURL(try required("--snapshot-root", in: options)),
                    expectedSourceRepository: try required("--source-repository", in: options),
                    expectedSourceRevision: try required("--expected-source-revision", in: options),
                    expectedEngineRevision: try required("--expected-engine-revision", in: options),
                    expectedEngineCodeDirectoryHash: try required("--expected-engine-cdhash", in: options)
                )
            )
        } catch {
            emitStaticEvidence(staticEvidenceBlocked("QC.CLI.INVALID_ARGUMENTS", "Static evidence command arguments are invalid."))
        }

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
            allowed: ["--profile", "--policy", "--repository-root", "--manifest"]
        )
        let profile = try required("--profile", in: options)
        let policy = try required("--policy", in: options)
        let repositoryRoot = try required("--repository-root", in: options)
        let response: StaticWorkerResponse
        if let manifest = options["--manifest"] {
            response = QualityCommands.staticEvidenceWorkerResponse(
                profileData: try boundedFileData(at: fileURL(profile), maximumBytes: StaticEvidenceInputSnapshots.maximumInputBytes),
                policyData: try boundedFileData(at: fileURL(policy), maximumBytes: StaticEvidenceInputSnapshots.maximumInputBytes),
                manifestData: try boundedFileData(at: fileURL(manifest), maximumBytes: GitTreeStaticSnapshot.maximumManifestBytes)
            )
        } else {
            response = QualityCommands.staticWorkerResponse(
                profileURL: fileURL(profile),
                policyURL: fileURL(policy),
                repositoryRoot: fileURL(repositoryRoot)
            )
        }
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
