import Foundation

@main
struct EngineBuildProvenanceGenerator {
    static func main() throws {
        let values = CommandLine.arguments
        guard values.count == 5, values[1] == "--package-root", values[3] == "--output" else {
            throw GeneratorError.invalidArguments
        }
        let root = URL(fileURLWithPath: values[2], isDirectory: true).standardizedFileURL
        let output = URL(fileURLWithPath: values[4])
        let revision = git(["rev-parse", "HEAD"], root: root) ?? ""
        let rootMatches = git(["rev-parse", "--show-toplevel"], root: root)
            .map { URL(fileURLWithPath: $0).standardizedFileURL == root } ?? false
        let clean = git(["status", "--porcelain=v1", "--untracked-files=all"], root: root) == ""
        let indexFlags = git(["ls-files", "-v"], root: root) ?? ""
        let trusted = rootMatches && clean && revision.count == 40 && indexFlags
            .split(separator: "\n", omittingEmptySubsequences: true)
            .allSatisfy { $0.first == "H" }
        let source = """
        enum EngineBuildProvenance {
            static let revision = \(swiftString(revision))
            static let isTrusted = \(trusted ? "true" : "false")
        }
        """
        try FileManager.default.createDirectory(at: output.deletingLastPathComponent(), withIntermediateDirectories: true)
        try source.data(using: .utf8)!.write(to: output, options: .atomic)
    }

    private static func git(_ arguments: [String], root: URL) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["-C", root.path] + arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0,
                  let value = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) else {
                return nil
            }
            return value.trimmingCharacters(in: .whitespacesAndNewlines)
        } catch {
            return nil
        }
    }

    private static func swiftString(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}

private enum GeneratorError: Error {
    case invalidArguments
}
