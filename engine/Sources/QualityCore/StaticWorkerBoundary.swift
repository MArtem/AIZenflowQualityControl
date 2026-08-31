import Darwin
import Foundation

package struct BoundedProcessResult: Sendable {
    package let output: Data
    package let terminationStatus: Int32?
    package let exitedNormally: Bool
    package let timedOut: Bool
    package let outputLimitExceeded: Bool
    package let outputDrainCompleted: Bool

    package init(
        output: Data,
        terminationStatus: Int32?,
        exitedNormally: Bool,
        timedOut: Bool,
        outputLimitExceeded: Bool,
        outputDrainCompleted: Bool
    ) {
        self.output = output
        self.terminationStatus = terminationStatus
        self.exitedNormally = exitedNormally
        self.timedOut = timedOut
        self.outputLimitExceeded = outputLimitExceeded
        self.outputDrainCompleted = outputDrainCompleted
    }
}

private final class BoundedOutputAccumulator: @unchecked Sendable {
    private let lock = NSLock()
    private let maximumBytes: Int
    private var storage = Data()
    private var exceededLimit = false
    private var readFailed = false

    init(maximumBytes: Int) {
        self.maximumBytes = maximumBytes
    }

    func append(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }

        let remainingCapacity = maximumBytes - storage.count
        if data.count > remainingCapacity {
            exceededLimit = true
        }
        if remainingCapacity > 0 {
            storage.append(data.prefix(remainingCapacity))
        }
    }

    func markReadFailure() {
        lock.lock()
        defer { lock.unlock() }
        readFailed = true
    }

    func snapshot() -> (data: Data, exceededLimit: Bool, readFailed: Bool) {
        lock.lock()
        defer { lock.unlock() }
        return (storage, exceededLimit, readFailed)
    }
}

package final class ProcessExitMonitor: @unchecked Sendable {
    private let source: any DispatchSourceProcess

    package init(
        processIdentifier: pid_t,
        onExit: @escaping @Sendable () -> Void
    ) {
        precondition(processIdentifier > 0)

        source = DispatchSource.makeProcessSource(
            identifier: processIdentifier,
            eventMask: .exit,
            queue: DispatchQueue.global(qos: .userInitiated)
        )
        source.setEventHandler(handler: onExit)
        source.resume()
    }

    deinit {
        source.cancel()
    }
}

package enum BoundedProcessRunner {
    private static let terminationGraceSeconds = 1.0
    private static let drainGraceSeconds = 1.0

    package static func run(
        _ process: Process,
        timeoutSeconds: TimeInterval,
        maximumOutputBytes: Int,
        validateLaunchedProcess: @Sendable (pid_t) -> Bool = { _ in true }
    ) throws -> BoundedProcessResult {
        precondition(
            timeoutSeconds.isFinite && timeoutSeconds > 0 && timeoutSeconds <= 3_600
        )
        precondition(maximumOutputBytes > 0)

        let outputPipe = Pipe()
        let output = BoundedOutputAccumulator(maximumBytes: maximumOutputBytes)
        let outputDrained = DispatchSemaphore(value: 0)
        let processTerminated = DispatchSemaphore(value: 0)

        process.standardOutput = outputPipe
        process.terminationHandler = { _ in
            processTerminated.signal()
        }

        try process.run()
        guard validateLaunchedProcess(process.processIdentifier) else {
            terminateBoundedly(process, processTerminated: processTerminated)
            outputPipe.fileHandleForReading.closeFile()
            throw BoundedProcessRunnerError.identityRejected
        }

        DispatchQueue.global(qos: .utility).async {
            do {
                while let chunk = try outputPipe.fileHandleForReading.read(upToCount: 64 * 1_024),
                      !chunk.isEmpty {
                    output.append(chunk)
                }
            } catch {
                output.markReadFailure()
            }
            outputDrained.signal()
        }

        let timedOut = processTerminated.wait(
            timeout: deadline(after: timeoutSeconds)
        ) == .timedOut

        if timedOut {
            terminateBoundedly(process, processTerminated: processTerminated)
        }

        let drainReachedEnd = outputDrained.wait(
            timeout: deadline(after: drainGraceSeconds)
        ) == .success
        if !drainReachedEnd {
            outputPipe.fileHandleForReading.closeFile()
        }

        let snapshot = output.snapshot()
        let hasTerminated = !process.isRunning

        return BoundedProcessResult(
            output: snapshot.data,
            terminationStatus: hasTerminated ? process.terminationStatus : nil,
            exitedNormally: hasTerminated && process.terminationReason == .exit,
            timedOut: timedOut,
            outputLimitExceeded: snapshot.exceededLimit,
            outputDrainCompleted: drainReachedEnd && !snapshot.readFailed
        )
    }

    private static func deadline(after seconds: TimeInterval) -> DispatchTime {
        let nanoseconds = Int(seconds * 1_000_000_000)
        return .now() + .nanoseconds(nanoseconds)
    }

    private static func terminateBoundedly(
        _ process: Process,
        processTerminated: DispatchSemaphore
    ) {
        process.terminate()
        if processTerminated.wait(
            timeout: deadline(after: terminationGraceSeconds)
        ) == .timedOut,
           process.isRunning {
            Darwin.kill(process.processIdentifier, SIGKILL)
            _ = processTerminated.wait(
                timeout: deadline(after: terminationGraceSeconds)
            )
        }
    }
}

package enum BoundedProcessRunnerError: Error {
    case identityRejected
}

package enum StaticWorkerBoundary {
    package static let hardTimeoutSeconds = 245.0
    package static let completionReserveSeconds = 5.0
    package static let maximumOutputBytes = 8 * 1_024 * 1_024

    package static func timeoutSeconds(
        deadlineEpochSeconds: String?,
        nowEpochSeconds: TimeInterval
    ) -> TimeInterval? {
        guard let deadlineEpochSeconds else {
            return hardTimeoutSeconds
        }
        guard let deadline = TimeInterval(deadlineEpochSeconds),
              deadline.isFinite,
              nowEpochSeconds.isFinite else {
            return nil
        }

        let available = deadline - nowEpochSeconds - completionReserveSeconds
        guard available.isFinite, available > 0 else {
            return nil
        }
        return min(hardTimeoutSeconds, available)
    }

    package static func boundedDeadlineEpochSeconds(
        inheritedDeadlineEpochSeconds: String?,
        nowEpochSeconds: TimeInterval
    ) -> String {
        let localDeadline = nowEpochSeconds + hardTimeoutSeconds
        guard let inheritedDeadlineEpochSeconds else {
            return String(localDeadline)
        }
        guard let inheritedDeadline = TimeInterval(inheritedDeadlineEpochSeconds),
              inheritedDeadline.isFinite else {
            return inheritedDeadlineEpochSeconds
        }
        return String(min(inheritedDeadline, localDeadline))
    }

    package static func deadlineBudgetFailure() -> QualityReport {
        blocked(
            id: "QC.STATIC.DEADLINE_BUDGET",
            message: "Static worker could not start within the remaining workflow deadline."
        )
    }

    package static func report(for result: BoundedProcessResult) -> QualityReport {
        if result.timedOut {
            return blocked(
                id: "QC.STATIC.HARD_TIMEOUT",
                message: "Static worker exceeded the hard process deadline and was terminated."
            )
        }
        guard result.outputDrainCompleted else {
            return blocked(
                id: "QC.STATIC.WORKER_OUTPUT_BLOCKED",
                message: "Static worker output could not be drained within its bounded deadline."
            )
        }
        guard !result.outputLimitExceeded else {
            return blocked(
                id: "QC.STATIC.WORKER_OUTPUT_LIMIT",
                message: "Static worker output exceeded the immutable byte limit."
            )
        }
        return validatedObservation(for: result)?.report ?? workerFailure()
    }

    package static func validatedObservation(
        for result: BoundedProcessResult
    ) -> ValidatedStaticWorkerObservation? {
        if result.timedOut {
            return nil
        }

        guard result.outputDrainCompleted else {
            return nil
        }

        guard !result.outputLimitExceeded else {
            return nil
        }

        guard result.exitedNormally,
              let terminationStatus = result.terminationStatus else {
            return nil
        }

        let response: StaticWorkerResponse
        do {
            try JSONDocumentConstraints.rejectDuplicateObjectKeys(in: result.output)
            response = try JSONDecoder().decode(
                StaticWorkerResponse.self,
                from: result.output
            )
        } catch {
            return nil
        }

        guard
              response.schemaVersion == StaticWorkerResponse.currentSchemaVersion,
              response.report.schemaVersion == 1,
              response.report.command == "static",
              hasValidReportEnvelope(response.report),
              response.hasValidDigests else {
            return nil
        }

        let normalizedReport = QualityReport(
            command: response.report.command,
            checks: response.report.checks
        )
        let expectedExit: Int32
        switch normalizedReport.status {
        case .pass:
            expectedExit = 0
        case .fail:
            expectedExit = 1
        case .blocked:
            expectedExit = 2
        }

        guard normalizedReport.status == response.report.status,
              terminationStatus == expectedExit else {
            return nil
        }

        return ValidatedStaticWorkerObservation(
            report: normalizedReport,
            profileSHA256: response.profileSHA256,
            policySHA256: response.policySHA256,
            sourceManifestSHA256: response.sourceManifestSHA256
        )
    }

    private static func workerFailure() -> QualityReport {
        blocked(
            id: "QC.STATIC.WORKER_FAILURE",
            message: "Static worker did not return a valid report and matching terminal exit."
        )
    }

    private static func hasValidReportEnvelope(_ report: QualityReport) -> Bool {
        guard !report.checks.isEmpty,
              report.checks.count <= StaticEvidenceResultLimits.maximumChecks else {
            return false
        }
        return report.checks.allSatisfy { check in
            isBoundedNonEmptyString(check.id)
                && isBoundedNonEmptyString(check.message)
                && (check.path == nil || isBoundedNonEmptyString(check.path!))
        }
    }

    private static func isBoundedNonEmptyString(_ value: String) -> Bool {
        var count = 0
        var hasNonWhitespace = false
        for scalar in value.unicodeScalars.prefix(StaticEvidenceResultLimits.maximumStringScalars + 1) {
            count += 1
            if scalar != " " && scalar != "\t" && scalar != "\n" && scalar != "\r" {
                hasNonWhitespace = true
            }
        }
        return count <= StaticEvidenceResultLimits.maximumStringScalars && hasNonWhitespace
    }

    private static func blocked(id: String, message: String) -> QualityReport {
        QualityReport(
            command: "static",
            checks: [
                QualityCheck(
                    id: id,
                    status: .blocked,
                    message: message
                )
            ]
        )
    }
}

package struct ValidatedStaticWorkerObservation: Sendable {
    package let report: QualityReport
    package let profileSHA256: String?
    package let policySHA256: String?
    package let sourceManifestSHA256: String?

    fileprivate init(
        report: QualityReport,
        profileSHA256: String?,
        policySHA256: String?,
        sourceManifestSHA256: String?
    ) {
        self.report = report
        self.profileSHA256 = profileSHA256
        self.policySHA256 = policySHA256
        self.sourceManifestSHA256 = sourceManifestSHA256
    }
}

package struct StaticWorkerResponse: Codable, Sendable {
    package static let currentSchemaVersion = 1

    package let schemaVersion: Int
    package let report: QualityReport
    package let profileSHA256: String?
    package let policySHA256: String?
    package let sourceManifestSHA256: String?

    package init(
        report: QualityReport,
        profileSHA256: String?,
        policySHA256: String?,
        sourceManifestSHA256: String? = nil
    ) {
        schemaVersion = Self.currentSchemaVersion
        self.report = report
        self.profileSHA256 = profileSHA256
        self.policySHA256 = policySHA256
        self.sourceManifestSHA256 = sourceManifestSHA256
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion
        case report
        case profileSHA256
        case policySHA256
        case sourceManifestSHA256
    }

    package init(from decoder: any Decoder) throws {
        let allKeys = try decoder.container(keyedBy: StaticWorkerResponseCodingKey.self)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard Set(allKeys.allKeys.map(\.stringValue))
            == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw StaticWorkerResponseDecodingError.invalidEnvelope
        }
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        report = try container.decode(QualityReport.self, forKey: .report)
        profileSHA256 = try container.decodeIfPresent(String.self, forKey: .profileSHA256)
        policySHA256 = try container.decodeIfPresent(String.self, forKey: .policySHA256)
        sourceManifestSHA256 = try container.decodeIfPresent(String.self, forKey: .sourceManifestSHA256)
    }

    package func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(report, forKey: .report)
        if let profileSHA256 {
            try container.encode(profileSHA256, forKey: .profileSHA256)
        } else {
            try container.encodeNil(forKey: .profileSHA256)
        }
        if let policySHA256 {
            try container.encode(policySHA256, forKey: .policySHA256)
        } else {
            try container.encodeNil(forKey: .policySHA256)
        }
        if let sourceManifestSHA256 {
            try container.encode(sourceManifestSHA256, forKey: .sourceManifestSHA256)
        } else {
            try container.encodeNil(forKey: .sourceManifestSHA256)
        }
    }

    fileprivate var hasValidDigests: Bool {
        let profileDigestIsValid = profileSHA256.map(isLowercaseSHA256) ?? false
        let policyDigestIsValid = policySHA256.map(isLowercaseSHA256) ?? false
        let manifestDigestIsValid = sourceManifestSHA256.map(isLowercaseSHA256) ?? true
        guard (profileSHA256 == nil || profileDigestIsValid)
            && (policySHA256 == nil || policyDigestIsValid)
            && manifestDigestIsValid else {
            return false
        }
        if profileDigestIsValid && policyDigestIsValid {
            return true
        }
        return missingDigestsMatchUnscannedInputs
    }

    private func isLowercaseSHA256(_ digest: String) -> Bool {
        let bytes = digest.utf8
        return bytes.count == 64 && bytes.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
    }

    private var missingDigestsMatchUnscannedInputs: Bool {
        let unreadableInputIDs: Set<String> = [
            "QC.PROFILE.UNREADABLE",
            "QC.POLICY.UNREADABLE"
        ]
        let checkIDs = Set(report.checks.map(\.id))
        guard report.status == .fail, !checkIDs.isEmpty else {
            return false
        }

        if profileSHA256 == nil,
           checkIDs.isSubset(of: unreadableInputIDs),
           checkIDs.contains("QC.PROFILE.UNREADABLE") {
            return true
        }

        guard policySHA256 == nil else {
            return false
        }
        if checkIDs.contains("QC.POLICY.UNREADABLE") {
            return true
        }
        return profileSHA256 != nil
            && report.checks.allSatisfy {
                $0.status == .fail && $0.id.hasPrefix("QC.PROFILE.")
            }
    }
}

private struct StaticWorkerResponseCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

private enum StaticWorkerResponseDecodingError: Error {
    case invalidEnvelope
}
