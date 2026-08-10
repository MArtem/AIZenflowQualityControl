import Foundation

@main
struct EngineBuildProvenanceGenerator {
    static func main() throws {
        let values = CommandLine.arguments
        guard values.count >= 5, values[1] == "--package-root", values[3] == "--output" else {
            throw GeneratorError.invalidArguments
        }
        let root = URL(fileURLWithPath: values[2], isDirectory: true).standardizedFileURL
        let output = URL(fileURLWithPath: values[4])
        let inputPaths = (try? parseInputs(values.dropFirst(5), root: root)) ?? []
        let revision = git(["rev-parse", "HEAD"], root: root) ?? ""
        let rootMatches = git(["rev-parse", "--show-toplevel"], root: root)
            .map { URL(fileURLWithPath: $0).standardizedFileURL == root } ?? false
        let trusted = !inputPaths.isEmpty && rootMatches && revision.count == 40 && inputPaths.allSatisfy {
            matchesHeadBlob(at: $0, revision: revision, root: root)
        }
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
        var environment = ProcessInfo.processInfo.environment
        environment["GIT_NO_REPLACE_OBJECTS"] = "1"
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
        process.environment = environment
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
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

    private static func parseInputs(_ values: ArraySlice<String>, root: URL) throws -> [String] {
        guard values.count.isMultiple(of: 2) else { throw GeneratorError.invalidArguments }
        var paths: [String] = []
        var index = values.startIndex
        while index < values.endIndex {
            guard values[index] == "--input" else { throw GeneratorError.invalidArguments }
            let url = URL(fileURLWithPath: values[values.index(after: index)]).standardizedFileURL
            guard url.path.hasPrefix(root.path + "/") else { throw GeneratorError.invalidArguments }
            paths.append(String(url.path.dropFirst(root.path.count + 1)))
            index = values.index(index, offsetBy: 2)
        }
        return paths.sorted()
    }

    private static func matchesHeadBlob(at relativePath: String, revision: String, root: URL) -> Bool {
        guard let working = git(["hash-object", "--", relativePath], root: root),
              let expected = git(["rev-parse", "\(revision):\(relativePath)"], root: root) else {
            return false
        }
        return working == expected
    }

    private static func swiftString(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}

private enum GeneratorError: Error {
    case invalidArguments
}
