import CryptoKit
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
        let data = try JSONEncoder().encode(
            StaticWorkerResponse(
                report: expected,
                profileSHA256: String(repeating: "a", count: 64),
                policySHA256: String(repeating: "b", count: 64)
            )
        )
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

    @Test("A static evidence worker report cannot exceed the public schema check ceiling")
    func reportCheckLimitFailsClosed() throws {
        let checks = (0...StaticEvidenceResultLimits.maximumChecks).map { index in
            QualityCheck(id: "QC.STATIC.\(index)", status: .pass, message: "Passed.")
        }
        let data = try JSONEncoder().encode(
            StaticWorkerResponse(
                report: QualityReport(command: "static", checks: checks),
                profileSHA256: String(repeating: "a", count: 64),
                policySHA256: String(repeating: "b", count: 64)
            )
        )
        let result = BoundedProcessResult(
            output: data,
            terminationStatus: 0,
            exitedNormally: true,
            timedOut: false,
            outputLimitExceeded: false,
            outputDrainCompleted: true
        )

        #expect(StaticWorkerBoundary.report(for: result).status == .blocked)
    }

    @Test("The worker binds its report to the exact profile and policy bytes it loaded")
    func workerResponseRecordsExactInputDigests() throws {
        let repositoryRoot = URL(fileURLWithPath: #filePath, isDirectory: false)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let profileURL = repositoryRoot.appendingPathComponent("fixtures/profiles/valid-minimal.json")
        let policyURL = repositoryRoot.appendingPathComponent("policies/static-policy.json")
        let profileData = try Data(contentsOf: profileURL)
        let policyData = try Data(contentsOf: policyURL)
        let profileSnapshot = try ProfileSnapshot(data: profileData)

        let response = QualityCommands.staticWorkerResponse(
            profileURL: profileURL,
            policyURL: policyURL,
            repositoryRoot: repositoryRoot
        )

        #expect(response.profileSHA256 == profileSnapshot.sha256)
        #expect(response.policySHA256 == digest(policyData))
    }

    @Test("Unreadable input reports preserve explicit null snapshot digests")
    func unreadableInputReportIsPreserved() throws {
        let expected = QualityReport(
            command: "static",
            checks: [
                QualityCheck(
                    id: "QC.PROFILE.UNREADABLE",
                    status: .fail,
                    message: "Project profile could not be decoded."
                )
            ]
        )
        let data = try JSONEncoder().encode(
            StaticWorkerResponse(
                report: expected,
                profileSHA256: nil,
                policySHA256: nil
            )
        )
        let result = BoundedProcessResult(
            output: data,
            terminationStatus: 1,
            exitedNormally: true,
            timedOut: false,
            outputLimitExceeded: false,
            outputDrainCompleted: true
        )

        let report = StaticWorkerBoundary.report(for: result)

        #expect(report.status == .fail)
        #expect(report.checks.map(\.id) == ["QC.PROFILE.UNREADABLE"])
    }

    @Test("A profile contract failure may preserve an unavailable policy snapshot")
    func profileFailureWithUnavailablePolicyIsPreserved() throws {
        let expected = QualityReport(
            command: "static",
            checks: [
                QualityCheck(
                    id: "QC.PROFILE.INVALID_SANDBOX_ROOT",
                    status: .fail,
                    message: "Sandbox root must be absolute."
                )
            ]
        )
        let data = try JSONEncoder().encode(
            StaticWorkerResponse(
                report: expected,
                profileSHA256: String(repeating: "a", count: 64),
                policySHA256: nil
            )
        )
        let result = BoundedProcessResult(
            output: data,
            terminationStatus: 1,
            exitedNormally: true,
            timedOut: false,
            outputLimitExceeded: false,
            outputDrainCompleted: true
        )

        let report = StaticWorkerBoundary.report(for: result)

        #expect(report.status == .fail)
        #expect(report.checks.map(\.id) == ["QC.PROFILE.INVALID_SANDBOX_ROOT"])
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

    @Test("A rejected launched process is terminated before its output can be trusted")
    func processIdentityRejectionFailsClosed() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["5"]

        #expect(throws: BoundedProcessRunnerError.self) {
            try BoundedProcessRunner.run(
                process,
                timeoutSeconds: 1,
                maximumOutputBytes: 1_024,
                validateLaunchedProcess: { _ in false }
            )
        }
        #expect(!process.isRunning)
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

private func digest(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
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
    case missingPassingSnapshotDigests
    case malformedSnapshotDigest
    case unsupportedWorkerSchema
    case unknownEnvelopeProperty
    case duplicateEnvelopeKey
    case nonASCIISnapshotDigest
    case unboundFailSnapshotDigests
    case unboundBlockedSnapshotDigests

    func result() throws -> BoundedProcessResult {
        let passingReport = QualityReport(
            command: "static",
            checks: [
                QualityCheck(id: "QC.STATIC.SCAN", status: .pass, message: "pass")
            ]
        )
        let passingData = try JSONEncoder().encode(
            StaticWorkerResponse(
                report: passingReport,
                profileSHA256: String(repeating: "a", count: 64),
                policySHA256: String(repeating: "b", count: 64)
            )
        )

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
        case .missingPassingSnapshotDigests:
            let missingDigests = try JSONEncoder().encode(
                StaticWorkerResponse(
                    report: passingReport,
                    profileSHA256: nil,
                    policySHA256: nil
                )
            )
            return base(output: missingDigests)
        case .malformedSnapshotDigest:
            let malformedDigest = try JSONEncoder().encode(
                StaticWorkerResponse(
                    report: passingReport,
                    profileSHA256: "not-a-sha256",
                    policySHA256: String(repeating: "b", count: 64)
                )
            )
            return base(output: malformedDigest)
        case .unsupportedWorkerSchema:
            let response = try JSONSerialization.jsonObject(with: passingData)
            guard var object = response as? [String: Any] else {
                throw InvalidWorkerResultError.invalidFixture
            }
            object["schemaVersion"] = 2
            return base(output: try JSONSerialization.data(withJSONObject: object))
        case .unknownEnvelopeProperty:
            let response = try JSONSerialization.jsonObject(with: passingData)
            guard var object = response as? [String: Any] else {
                throw InvalidWorkerResultError.invalidFixture
            }
            object["unexpected"] = true
            return base(output: try JSONSerialization.data(withJSONObject: object))
        case .duplicateEnvelopeKey:
            let duplicateReport = #"{"checks":[{"id":"QC.STATIC.SCAN","message":"pass","status":"PASS"}],"command":"static","schemaVersion":1,"status":"PASS"}"#
            let duplicateEnvelope = """
            {"schemaVersion":1,"report":\(duplicateReport),"report":\(duplicateReport),"profileSHA256":"\(String(repeating: "a", count: 64))","policySHA256":"\(String(repeating: "b", count: 64))"}
            """
            return base(output: Data(duplicateEnvelope.utf8))
        case .nonASCIISnapshotDigest:
            let nonASCII = try JSONEncoder().encode(
                StaticWorkerResponse(
                    report: passingReport,
                    profileSHA256: String(repeating: "١", count: 64),
                    policySHA256: String(repeating: "b", count: 64)
                )
            )
            return base(output: nonASCII)
        case .unboundFailSnapshotDigests:
            let failingReport = QualityReport(
                command: "static",
                checks: [
                    QualityCheck(
                        id: "QC.STATIC.FORBIDDEN_ARTIFACT",
                        status: .fail,
                        message: "forbidden"
                    )
                ]
            )
            let unboundFailure = try JSONEncoder().encode(
                StaticWorkerResponse(
                    report: failingReport,
                    profileSHA256: nil,
                    policySHA256: nil
                )
            )
            return base(output: unboundFailure, terminationStatus: 1)
        case .unboundBlockedSnapshotDigests:
            let blockedReport = QualityReport(
                command: "static",
                checks: [
                    QualityCheck(
                        id: "QC.STATIC.TIMEOUT",
                        status: .blocked,
                        message: "timed out"
                    )
                ]
            )
            let unboundBlocked = try JSONEncoder().encode(
                StaticWorkerResponse(
                    report: blockedReport,
                    profileSHA256: nil,
                    policySHA256: nil
                )
            )
            return base(output: unboundBlocked, terminationStatus: 2)
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

private enum InvalidWorkerResultError: Error {
    case invalidFixture
}
