import CryptoKit
import Foundation

package struct XcodeBuildDestinationObservation: Equatable, Sendable {
    package let deviceID: String
    package let deviceName: String
    package let architecture: String
    package let modelName: String
    package let platform: String?
    package let osVersion: String
    package let osBuildNumber: String?
}

package struct XcodeBuildEvidenceObservation: Equatable, Sendable {
    package static let buildResultsSchemaVersion = "0.1.0"

    package let buildResultsSHA256: String
    package let buildLogSHA256: String
    package let actionTitle: String
    package let destination: XcodeBuildDestinationObservation
    package let startTime: Double
    package let endTime: Double
    package let warningCount: Int
    package let analyzerWarningCount: Int
    package let compiledSourcePaths: [String]
    package let compilerSectionCount: Int
}

package enum XcodeBuildEvidenceVerificationError: Error, Equatable {
    case buildProcessTimedOut
    case buildProcessOutputUnavailable
    case buildProcessFailed(Int32?)
    case buildResultsTooLarge
    case malformedBuildResults
    case unsuccessfulBuildResult
    case inconsistentIssueCounts
    case invalidBuildTiming
    case invalidBuildDestination
    case issueLimitExceeded
    case sourceMembership(XcodeBuildLogMembershipError)
}

/// Verifies mutually dependent observations from one completed Xcode build invocation.
///
/// This type deliberately does not establish result-bundle provenance. Its caller must obtain both
/// structured documents from the same fresh, supervisor-owned `.xcresult` after the observed
/// `xcodebuild` process terminates and must reject bundle replacement before treating this output as
/// authenticated evidence.
package enum XcodeBuildEvidenceVerifier {
    package static let maximumBuildResultsBytes = 8 * 1_024 * 1_024
    private static let maximumIssues = 10_000
    private static let maximumStringScalars = 4_096

    package static func verify(
        processResult: BoundedProcessResult,
        buildResultsData: Data,
        buildLogData: Data,
        repositoryRoot: URL,
        sourcePaths: [String]
    ) throws -> XcodeBuildEvidenceObservation {
        guard !processResult.timedOut else {
            throw XcodeBuildEvidenceVerificationError.buildProcessTimedOut
        }
        guard processResult.outputDrainCompleted,
              !processResult.outputLimitExceeded else {
            throw XcodeBuildEvidenceVerificationError.buildProcessOutputUnavailable
        }
        guard processResult.exitedNormally,
              processResult.terminationStatus == 0 else {
            throw XcodeBuildEvidenceVerificationError.buildProcessFailed(
                processResult.terminationStatus
            )
        }
        guard buildResultsData.count <= maximumBuildResultsBytes else {
            throw XcodeBuildEvidenceVerificationError.buildResultsTooLarge
        }

        let result: BuildResultsDocument
        do {
            try JSONDocumentConstraints.rejectDuplicateObjectKeys(in: buildResultsData)
            result = try JSONDecoder().decode(BuildResultsDocument.self, from: buildResultsData)
        } catch {
            throw XcodeBuildEvidenceVerificationError.malformedBuildResults
        }

        guard result.status == "succeeded",
              result.errors.isEmpty,
              result.errorCount == nil || result.errorCount == 0 else {
            throw XcodeBuildEvidenceVerificationError.unsuccessfulBuildResult
        }
        guard (result.errorCount == nil || result.errorCount == result.errors.count),
              (result.warningCount == nil || result.warningCount == result.warnings.count),
              (result.analyzerWarningCount == nil
                  || result.analyzerWarningCount == result.analyzerWarnings.count) else {
            throw XcodeBuildEvidenceVerificationError.inconsistentIssueCounts
        }
        guard result.startTime.isFinite,
              result.endTime.isFinite,
              result.startTime > 0,
              result.endTime >= result.startTime else {
            throw XcodeBuildEvidenceVerificationError.invalidBuildTiming
        }
        guard isBoundedNonEmpty(result.actionTitle),
              result.destination.hasValidStrings else {
            throw XcodeBuildEvidenceVerificationError.invalidBuildDestination
        }

        let issueCount = result.analyzerWarnings.count
            + result.warnings.count
            + result.errors.count
        guard issueCount <= maximumIssues,
              result.allIssues.allSatisfy({ issue in
                  isBoundedNonEmpty(issue.issueType)
                      && isBoundedNonEmpty(issue.message)
                      && isBoundedOptional(issue.targetName)
                      && isBoundedOptional(issue.sourceURL)
                      && isBoundedOptional(issue.className)
              }) else {
            throw XcodeBuildEvidenceVerificationError.issueLimitExceeded
        }

        let membership: XcodeBuildLogMembershipObservation
        do {
            membership = try XcodeBuildLogMembershipExtractor.extract(
                logData: buildLogData,
                repositoryRoot: repositoryRoot,
                sourcePaths: sourcePaths
            )
        } catch let error as XcodeBuildLogMembershipError {
            throw XcodeBuildEvidenceVerificationError.sourceMembership(error)
        }

        return XcodeBuildEvidenceObservation(
            buildResultsSHA256: SHA256.hash(data: buildResultsData).map {
                String(format: "%02x", $0)
            }.joined(),
            buildLogSHA256: membership.buildLogSHA256,
            actionTitle: result.actionTitle,
            destination: XcodeBuildDestinationObservation(
                deviceID: result.destination.deviceID,
                deviceName: result.destination.deviceName,
                architecture: result.destination.architecture,
                modelName: result.destination.modelName,
                platform: result.destination.platform,
                osVersion: result.destination.osVersion,
                osBuildNumber: result.destination.osBuildNumber
            ),
            startTime: result.startTime,
            endTime: result.endTime,
            warningCount: result.warningCount ?? result.warnings.count,
            analyzerWarningCount: result.analyzerWarningCount
                ?? result.analyzerWarnings.count,
            compiledSourcePaths: membership.compiledSourcePaths,
            compilerSectionCount: membership.compilerSectionCount
        )
    }

    fileprivate static func isBoundedNonEmpty(_ value: String) -> Bool {
        var scalarCount = 0
        var hasNonWhitespace = false
        for scalar in value.unicodeScalars.prefix(maximumStringScalars + 1) {
            scalarCount += 1
            if scalar != " " && scalar != "\t" && scalar != "\n" && scalar != "\r" {
                hasNonWhitespace = true
            }
        }
        return scalarCount <= maximumStringScalars && hasNonWhitespace
    }

    fileprivate static func isBoundedOptional(_ value: String?) -> Bool {
        value == nil || isBoundedNonEmpty(value!)
    }
}

private struct BuildResultsDocument: Decodable {
    let actionTitle: String
    let destination: BuildResultsDestination
    let startTime: Double
    let endTime: Double
    let status: String?
    let analyzerWarningCount: Int?
    let errorCount: Int?
    let warningCount: Int?
    let analyzerWarnings: [BuildResultsIssue]
    let warnings: [BuildResultsIssue]
    let errors: [BuildResultsIssue]

    var allIssues: [BuildResultsIssue] {
        analyzerWarnings + warnings + errors
    }
}

private struct BuildResultsDestination: Decodable {
    let deviceID: String
    let deviceName: String
    let architecture: String
    let modelName: String
    let platform: String?
    let osVersion: String
    let osBuildNumber: String?

    private enum CodingKeys: String, CodingKey {
        case deviceID = "deviceId"
        case deviceName
        case architecture
        case modelName
        case platform
        case osVersion
        case osBuildNumber
    }

    var hasValidStrings: Bool {
        XcodeBuildEvidenceVerifier.isBoundedNonEmpty(deviceID)
            && XcodeBuildEvidenceVerifier.isBoundedNonEmpty(deviceName)
            && XcodeBuildEvidenceVerifier.isBoundedNonEmpty(architecture)
            && XcodeBuildEvidenceVerifier.isBoundedNonEmpty(modelName)
            && XcodeBuildEvidenceVerifier.isBoundedOptional(platform)
            && XcodeBuildEvidenceVerifier.isBoundedNonEmpty(osVersion)
            && XcodeBuildEvidenceVerifier.isBoundedOptional(osBuildNumber)
    }
}

private struct BuildResultsIssue: Decodable {
    let issueType: String
    let message: String
    let targetName: String?
    let sourceURL: String?
    let className: String?
}
