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

package enum BoundedProcessRunner {
    private static let terminationGraceSeconds = 1.0
    private static let drainGraceSeconds = 1.0

    package static func run(
        _ process: Process,
        timeoutSeconds: TimeInterval,
        maximumOutputBytes: Int
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
}

package enum StaticWorkerBoundary {
    package static let hardTimeoutSeconds = 245.0
    package static let maximumOutputBytes = 8 * 1_024 * 1_024

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

        guard result.exitedNormally,
              let terminationStatus = result.terminationStatus,
              let decodedReport = try? JSONDecoder().decode(
                  QualityReport.self,
                  from: result.output
              ),
              decodedReport.schemaVersion == 1,
              decodedReport.command == "static" else {
            return workerFailure()
        }

        let normalizedReport = QualityReport(
            command: decodedReport.command,
            checks: decodedReport.checks
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

        guard normalizedReport.status == decodedReport.status,
              terminationStatus == expectedExit else {
            return workerFailure()
        }

        return normalizedReport
    }

    private static func workerFailure() -> QualityReport {
        blocked(
            id: "QC.STATIC.WORKER_FAILURE",
            message: "Static worker did not return a valid report and matching terminal exit."
        )
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
