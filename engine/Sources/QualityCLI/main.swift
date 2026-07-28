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

let arguments = CommandLine.arguments
guard arguments.count >= 2 else {
    emit(
        QualityCommands.blockedUsage(
            command: "usage",
            message: "Expected doctor, validate-profile, or static."
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
            QualityCommands.staticScan(
                profileURL: fileURL(profile),
                policyURL: fileURL(policy),
                repositoryRoot: fileURL(repositoryRoot)
            )
        )

    default:
        emit(
            QualityCommands.blockedUsage(
                command: command,
                message: "Unknown command. Expected doctor, validate-profile, or static."
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
