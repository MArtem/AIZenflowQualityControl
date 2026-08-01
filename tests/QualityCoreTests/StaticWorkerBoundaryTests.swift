import Foundation
import Testing
@testable import QualityCore

@Suite("Static worker hard-boundary contracts")
struct StaticWorkerBoundaryTests {
    @Test("Workflow deadlines preserve a bounded completion reserve")
    func workflowDeadlineBudgetIsBounded() {
        #expect(
            StaticWorkerBoundary.timeoutSeconds(
                deadlineEpochSeconds: nil,
                nowEpochSeconds: 100
            ) == StaticWorkerBoundary.hardTimeoutSeconds
        )
        #expect(
            StaticWorkerBoundary.timeoutSeconds(
                deadlineEpochSeconds: "250",
                nowEpochSeconds: 100
            ) == 145
        )
        #expect(
            StaticWorkerBoundary.timeoutSeconds(
                deadlineEpochSeconds: "1000",
                nowEpochSeconds: 100
            ) == StaticWorkerBoundary.hardTimeoutSeconds
        )
        #expect(
            StaticWorkerBoundary.timeoutSeconds(
                deadlineEpochSeconds: "not-a-deadline",
                nowEpochSeconds: 100
            ) == nil
        )
        #expect(
            StaticWorkerBoundary.timeoutSeconds(
                deadlineEpochSeconds: "105",
                nowEpochSeconds: 100
            ) == nil
        )
        #expect(StaticWorkerBoundary.deadlineBudgetFailure().status == .blocked)
    }

    @Test("A process exit monitor observes termination")
    func processExitMonitorObservesTermination() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["5"]
        try process.run()
        defer {
            if process.isRunning {
                process.terminate()
            }
        }

        let processExited = DispatchSemaphore(value: 0)
        let monitor = ProcessExitMonitor(
            processIdentifier: process.processIdentifier
        ) {
            processExited.signal()
        }

        process.terminate()
        #expect(processExited.wait(timeout: .now() + 2) == .success)
        process.waitUntilExit()
        withExtendedLifetime(monitor) {}
    }

    @Test("A blocked child is terminated at the hard deadline")
    func hardDeadlineTerminatesBlockedChild() throws {
        let inputPipe = Pipe()
        defer {
            inputPipe.fileHandleForWriting.closeFile()
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/cat")
        process.standardInput = inputPipe

        let result = try BoundedProcessRunner.run(
            process,
            timeoutSeconds: 0.1,
            maximumOutputBytes: 1_024
        )
        let report = StaticWorkerBoundary.report(for: result)

        #expect(result.timedOut)
        #expect(!process.isRunning)
        #expect(report.status == .blocked)
        #expect(report.checks.map(\.id) == ["QC.STATIC.HARD_TIMEOUT"])
    }

    @Test("A valid worker report preserves status and terminal exit")
    func validWorkerReportIsPreserved() throws {
        let expected = QualityReport(
            command: "static",
            checks: [
                QualityCheck(
                    id: "QC.STATIC.SCAN",
                    status: .pass,
                    message: "Static scan completed."
                )
            ]
        )
        let data = try JSONEncoder().encode(expected)
        let result = BoundedProcessResult(
            output: data,
            terminationStatus: 0,
            exitedNormally: true,
            timedOut: false,
            outputLimitExceeded: false,
            outputDrainCompleted: true
        )

        let report = StaticWorkerBoundary.report(for: result)

        #expect(report.status == .pass)
        #expect(report.checks.map(\.id) == ["QC.STATIC.SCAN"])
    }

    @Test("The process runner drains bounded output and detects overflow")
    func processRunnerBoundsOutput() throws {
        let boundedProcess = Process()
        boundedProcess.executableURL = URL(fileURLWithPath: "/usr/bin/printf")
        boundedProcess.arguments = ["bounded"]

        let boundedResult = try BoundedProcessRunner.run(
            boundedProcess,
            timeoutSeconds: 1,
            maximumOutputBytes: 16
        )

        #expect(boundedResult.output == Data("bounded".utf8))
        #expect(boundedResult.terminationStatus == 0)
        #expect(boundedResult.exitedNormally)
        #expect(!boundedResult.timedOut)
        #expect(!boundedResult.outputLimitExceeded)
        #expect(boundedResult.outputDrainCompleted)

        let oversizedProcess = Process()
        oversizedProcess.executableURL = URL(fileURLWithPath: "/usr/bin/printf")
        oversizedProcess.arguments = ["oversized"]

        let oversizedResult = try BoundedProcessRunner.run(
            oversizedProcess,
            timeoutSeconds: 1,
            maximumOutputBytes: 4
        )

        #expect(oversizedResult.output == Data("over".utf8))
        #expect(oversizedResult.outputLimitExceeded)
        #expect(oversizedResult.outputDrainCompleted)
    }

    @Test(
        "Malformed, oversized, mismatched, and incompletely drained worker output never passes",
        arguments: InvalidWorkerResult.allCases
    )
    func invalidWorkerResultNeverPasses(_ input: InvalidWorkerResult) throws {
        let result = try input.result()
        let report = StaticWorkerBoundary.report(for: result)

        #expect(report.status == .blocked)
        #expect(report.checks.allSatisfy { $0.status != .pass })
    }
}

enum InvalidWorkerResult: String, CaseIterable, Sendable {
    case malformed
    case outputLimitExceeded
    case outputDrainBlocked
    case signalled
    case timeoutWithPassingOutput
    case unsupportedSchema
    case wrongCommand
    case emptyChecks
    case statusMismatch
    case exitMismatch

    func result() throws -> BoundedProcessResult {
        let passingReport = QualityReport(
            command: "static",
            checks: [
                QualityCheck(id: "QC.STATIC.SCAN", status: .pass, message: "pass")
            ]
        )
        let passingData = try JSONEncoder().encode(passingReport)

        switch self {
        case .malformed:
            return base(output: Data("not-json".utf8))
        case .outputLimitExceeded:
            return base(output: passingData, outputLimitExceeded: true)
        case .outputDrainBlocked:
            return base(output: passingData, outputDrainCompleted: false)
        case .signalled:
            return base(output: passingData, exitedNormally: false)
        case .timeoutWithPassingOutput:
            return base(output: passingData, timedOut: true)
        case .unsupportedSchema:
            let unsupported = Data(
                #"{"checks":[{"id":"QC.STATIC.SCAN","message":"pass","status":"PASS"}],"command":"static","schemaVersion":2,"status":"PASS"}"#.utf8
            )
            return base(output: unsupported)
        case .wrongCommand:
            let wrongCommand = Data(
                #"{"checks":[{"id":"QC.STATIC.SCAN","message":"pass","status":"PASS"}],"command":"doctor","schemaVersion":1,"status":"PASS"}"#.utf8
            )
            return base(output: wrongCommand)
        case .emptyChecks:
            let emptyChecks = Data(
                #"{"checks":[],"command":"static","schemaVersion":1,"status":"PASS"}"#.utf8
            )
            return base(output: emptyChecks)
        case .statusMismatch:
            let mismatched = Data(
                #"{"checks":[{"id":"QC.STATIC.SCAN","message":"pass","status":"BLOCKED"}],"command":"static","schemaVersion":1,"status":"PASS"}"#.utf8
            )
            return base(output: mismatched)
        case .exitMismatch:
            return base(output: passingData, terminationStatus: 1)
        }
    }

    private func base(
        output: Data,
        terminationStatus: Int32 = 0,
        exitedNormally: Bool = true,
        timedOut: Bool = false,
        outputLimitExceeded: Bool = false,
        outputDrainCompleted: Bool = true
    ) -> BoundedProcessResult {
        BoundedProcessResult(
            output: output,
            terminationStatus: terminationStatus,
            exitedNormally: exitedNormally,
            timedOut: timedOut,
            outputLimitExceeded: outputLimitExceeded,
            outputDrainCompleted: outputDrainCompleted
        )
    }
}
