import Darwin
import CryptoKit
import Foundation

public struct ValidationIssue: Codable, Equatable, Sendable {
    public let code: String
    public let path: String
    public let message: String

    public init(code: String, path: String, message: String) {
        self.code = code
        self.path = path
        self.message = message
    }
}

enum JSONDocumentConstraints {
    static let maximumBytes = 1_000_000
    static let maximumNestingDepth = 64

    static func loadData(
        from url: URL,
        maximumBytes limit: Int = maximumBytes
    ) throws -> Data {
        guard limit > 0, limit < Int.max else {
            throw JSONDocumentLimitError()
        }
        let descriptor = open(url.path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw JSONDocumentReadError()
        }
        defer { close(descriptor) }

        var fileStatus = stat()
        guard fstat(descriptor, &fileStatus) == 0,
              fileStatus.st_mode & S_IFMT == S_IFREG else {
            throw JSONDocumentReadError()
        }

        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)

        while true {
            let remainingCapacity = limit + 1 - data.count
            guard remainingCapacity > 0 else {
                throw JSONDocumentLimitError()
            }

            let requestedCount = min(buffer.count, remainingCapacity)
            let readCount = buffer.withUnsafeMutableBytes { bytes in
                read(descriptor, bytes.baseAddress, requestedCount)
            }

            if readCount == 0 {
                return data
            }
            if readCount < 0 {
                if errno == EINTR {
                    continue
                }
                throw JSONDocumentReadError()
            }

            data.append(contentsOf: buffer.prefix(Int(readCount)))
            guard data.count <= limit else {
                throw JSONDocumentLimitError()
            }
        }
    }

    static func rejectDuplicateObjectKeys(in data: Data) throws {
        guard String(data: data, encoding: .utf8) != nil else {
            throw UnsupportedJSONEncodingError()
        }
        var parser = JSONDuplicateKeyParser(data: data)
        try parser.validate()
    }
}

private struct JSONDocumentLimitError: Error {}
private struct JSONDocumentReadError: Error {}
private struct UnsupportedJSONEncodingError: Error {}
private struct DuplicateJSONKeyError: Error {}
private struct MalformedJSONStructureError: Error {}
private struct JSONNestingLimitError: Error {}

private struct JSONDuplicateKeyParser {
    private let bytes: [UInt8]
    private var index = 0

    init(data: Data) {
        let bytes = Array(data)
        if bytes.starts(with: [0xEF, 0xBB, 0xBF]) {
            self.bytes = Array(bytes.dropFirst(3))
        } else {
            self.bytes = bytes
        }
    }

    mutating func validate() throws {
        skipWhitespace()
        try parseValue(depth: 0)
        skipWhitespace()
        guard index == bytes.count else {
            throw MalformedJSONStructureError()
        }
    }

    private mutating func parseValue(depth: Int) throws {
        skipWhitespace()
        guard let byte = currentByte else {
            throw MalformedJSONStructureError()
        }

        switch byte {
        case 0x7B:
            guard depth < JSONDocumentConstraints.maximumNestingDepth else {
                throw JSONNestingLimitError()
            }
            try parseObject(depth: depth + 1)
        case 0x5B:
            guard depth < JSONDocumentConstraints.maximumNestingDepth else {
                throw JSONNestingLimitError()
            }
            try parseArray(depth: depth + 1)
        case 0x22:
            _ = try parseString()
        default:
            try parseScalar()
        }
    }

    private mutating func parseObject(depth: Int) throws {
        try consume(0x7B)
        skipWhitespace()
        if consumeIfPresent(0x7D) {
            return
        }

        var keys = Set<String>()
        while true {
            skipWhitespace()
            let key = try parseString()
            guard keys.insert(key).inserted else {
                throw DuplicateJSONKeyError()
            }

            skipWhitespace()
            try consume(0x3A)
            try parseValue(depth: depth)
            skipWhitespace()

            if consumeIfPresent(0x7D) {
                return
            }
            try consume(0x2C)
        }
    }

    private mutating func parseArray(depth: Int) throws {
        try consume(0x5B)
        skipWhitespace()
        if consumeIfPresent(0x5D) {
            return
        }

        while true {
            try parseValue(depth: depth)
            skipWhitespace()
            if consumeIfPresent(0x5D) {
                return
            }
            try consume(0x2C)
        }
    }

    private mutating func parseString() throws -> String {
        let start = index
        try consume(0x22)
        var isEscaped = false

        while let byte = currentByte {
            index += 1

            if isEscaped {
                isEscaped = false
                continue
            }
            if byte == 0x5C {
                isEscaped = true
                continue
            }
            if byte == 0x22 {
                let encodedString = Data(bytes[start..<index])
                return try JSONDecoder().decode(String.self, from: encodedString)
            }
        }

        throw MalformedJSONStructureError()
    }

    private mutating func parseScalar() throws {
        let start = index
        while let byte = currentByte,
              !isWhitespace(byte),
              ![0x2C, 0x5D, 0x7D].contains(byte) {
            index += 1
        }
        guard index > start else {
            throw MalformedJSONStructureError()
        }
    }

    private mutating func consume(_ expected: UInt8) throws {
        guard consumeIfPresent(expected) else {
            throw MalformedJSONStructureError()
        }
    }

    private mutating func consumeIfPresent(_ expected: UInt8) -> Bool {
        guard currentByte == expected else {
            return false
        }
        index += 1
        return true
    }

    private mutating func skipWhitespace() {
        while let byte = currentByte, isWhitespace(byte) {
            index += 1
        }
    }

    private func isWhitespace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
    }

    private var currentByte: UInt8? {
        index < bytes.count ? bytes[index] : nil
    }
}

public enum ProfileLoader {
    public static func load(from url: URL) throws -> ProjectProfile {
        try decodeProfile(
            from: JSONDocumentConstraints.loadData(from: url)
        )
    }

    public static func loadSnapshot(from url: URL) throws -> ProfileSnapshot {
        let data = try JSONDocumentConstraints.loadData(from: url)
        return try ProfileSnapshot(data: data)
    }

    static func decodeProfile(from data: Data) throws -> ProjectProfile {
        try JSONDocumentConstraints.rejectDuplicateObjectKeys(in: data)
        try validateClosedObjectProperties(in: data)
        return try JSONDecoder().decode(ProjectProfile.self, from: data)
    }

    private static func validateClosedObjectProperties(in data: Data) throws {
        guard let profile = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return
        }

        try rejectUnknownProperties(
            in: profile,
            allowed: [
                "schemaVersion",
                "project",
                "scheme",
                "sourcePaths",
                "mode",
                "permissions",
                "sandbox"
            ]
        )

        if let project = profile["project"] as? [String: Any] {
            try rejectUnknownProperties(in: project, allowed: ["kind", "path"])
        }

        if let permissions = profile["permissions"] as? [String: Any] {
            try rejectUnknownProperties(
                in: permissions,
                allowed: [
                    "testCreation",
                    "testModification",
                    "localTestExecution",
                    "githubExecution",
                    "uiTests",
                    "simulatorOrDevice",
                    "performanceOrInstruments"
                ]
            )
        }

        if let sandbox = profile["sandbox"] as? [String: Any] {
            try rejectUnknownProperties(in: sandbox, allowed: ["root", "cache"])
        }
    }

    private static func rejectUnknownProperties(
        in object: [String: Any],
        allowed: Set<String>
    ) throws {
        guard Set(object.keys).isSubset(of: allowed) else {
            throw UnknownProfilePropertyError()
        }
    }
}

public struct ProfileSnapshot: Sendable {
    public let profile: ProjectProfile
    public let sha256: String

    public init(data: Data) throws {
        guard data.count <= JSONDocumentConstraints.maximumBytes else {
            throw JSONDocumentLimitError()
        }
        profile = try ProfileLoader.decodeProfile(from: data)
        sha256 = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

private struct UnknownProfilePropertyError: Error {}

private enum ProfileValidationLimits {
    static let maximumSourcePaths = 256
    static let maximumIssues = 256
}

public enum ProfileValidator {
    public static func validate(_ profile: ProjectProfile) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []

        if profile.schemaVersion != 1 {
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.UNSUPPORTED_SCHEMA",
                    path: "schemaVersion",
                    message: "Only project profile schemaVersion 1 is supported."
                )
            )
        }

        issues.append(contentsOf: validateRelativePath(profile.project.path, field: "project.path"))

        switch profile.project.kind {
        case .xcodeProject where !profile.project.path.hasSuffix(".xcodeproj"):
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.PROJECT_KIND_MISMATCH",
                    path: "project.path",
                    message: "An xcodeproj profile path must end in .xcodeproj."
                )
            )
        case .xcodeWorkspace where !profile.project.path.hasSuffix(".xcworkspace"):
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.PROJECT_KIND_MISMATCH",
                    path: "project.path",
                    message: "An xcworkspace profile path must end in .xcworkspace."
                )
            )
        default:
            break
        }

        if profile.scheme.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.EMPTY_SCHEME",
                    path: "scheme",
                    message: "The scheme must be explicitly provided."
                )
            )
        }

        if profile.sourcePaths.isEmpty {
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.EMPTY_SOURCE_PATHS",
                    path: "sourcePaths",
                    message: "At least one explicit source path is required."
                )
            )
        }

        if profile.sourcePaths.count > ProfileValidationLimits.maximumSourcePaths {
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.SOURCE_PATH_LIMIT",
                    path: "sourcePaths",
                    message: "A profile may contain at most \(ProfileValidationLimits.maximumSourcePaths) source paths."
                )
            )
        } else {
            var acceptedSourceScopes: [(path: String, components: [String])] = []
            for (index, sourcePath) in profile.sourcePaths.enumerated() {
                let pathIssues = validateRelativePath(
                    sourcePath,
                    field: "sourcePaths[\(index)]"
                )
                issues.append(contentsOf: pathIssues)

                guard pathIssues.isEmpty else {
                    continue
                }

                let components = normalizedRelativePathComponents(sourcePath)
                if let overlappingScope = acceptedSourceScopes.first(where: {
                    isPrefix($0.components, of: components)
                        || isPrefix(components, of: $0.components)
                }) {
                    issues.append(
                        ValidationIssue(
                            code: "QC.PROFILE.OVERLAPPING_SOURCE_PATH",
                            path: "sourcePaths[\(index)]",
                            message: "Source paths must not duplicate or overlap another scope (\(overlappingScope.path))."
                        )
                    )
                } else {
                    acceptedSourceScopes.append((sourcePath, components))
                }
            }
        }

        if !isAbsolute(profile.sandbox.root) {
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.SANDBOX_ROOT_NOT_ABSOLUTE",
                    path: "sandbox.root",
                    message: "The sandbox root must be an absolute path."
                )
            )
        }

        if !isAbsolute(profile.sandbox.cache) {
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.CACHE_NOT_ABSOLUTE",
                    path: "sandbox.cache",
                    message: "The cache path must be an absolute path."
                )
            )
        } else if isAbsolute(profile.sandbox.root)
            && !isDescendant(profile.sandbox.cache, of: profile.sandbox.root) {
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.CACHE_OUTSIDE_SANDBOX",
                    path: "sandbox.cache",
                    message: "The cache path must remain inside the configured sandbox root."
                )
            )
        }

        return boundedIssues(issues)
    }

    static func resolve(relativePath: String, under root: URL) -> URL? {
        guard validateRelativePath(relativePath, field: "path").isEmpty else {
            return nil
        }

        let resolved = root.appendingPathComponent(relativePath).standardizedFileURL
        let rootPath = root.standardizedFileURL.path
        let resolvedPath = resolved.path

        guard isContained(resolvedPath, by: rootPath, allowingRoot: true) else {
            return nil
        }

        return resolved
    }

    static func resolvesWithinRepository(
        _ candidate: URL,
        root: URL,
        allowingRoot: Bool = true
    ) -> Bool {
        let resolvedRoot = root.resolvingSymlinksInPath().standardizedFileURL.path
        let resolvedCandidate = candidate.resolvingSymlinksInPath().standardizedFileURL.path
        return isContained(resolvedCandidate, by: resolvedRoot, allowingRoot: allowingRoot)
    }

    private static func validateRelativePath(
        _ value: String,
        field: String
    ) -> [ValidationIssue] {
        if value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return [
                ValidationIssue(
                    code: "QC.PROFILE.EMPTY_PATH",
                    path: field,
                    message: "The path must not be empty."
                )
            ]
        }

        if isAbsolute(value) || value.hasPrefix("~") {
            return [
                ValidationIssue(
                    code: "QC.PROFILE.ABSOLUTE_PROJECT_PATH",
                    path: field,
                    message: "Project-owned paths must be relative to the repository root."
                )
            ]
        }

        let components = value.split(separator: "/", omittingEmptySubsequences: false)
        if components.contains("..") {
            return [
                ValidationIssue(
                    code: "QC.PROFILE.PATH_TRAVERSAL",
                    path: field,
                    message: "Parent-directory traversal is forbidden."
                )
            ]
        }

        return []
    }

    private static func isAbsolute(_ value: String) -> Bool {
        (value as NSString).isAbsolutePath
    }

    private static func boundedIssues(_ issues: [ValidationIssue]) -> [ValidationIssue] {
        guard issues.count > ProfileValidationLimits.maximumIssues else {
            return issues
        }

        return Array(issues.prefix(ProfileValidationLimits.maximumIssues - 1)) + [
            ValidationIssue(
                code: "QC.PROFILE.ISSUE_LIMIT_REACHED",
                path: "$",
                message: "Profile validation stopped reporting after reaching the issue limit."
            )
        ]
    }

    private static func normalizedRelativePathComponents(_ value: String) -> [String] {
        value
            .split(separator: "/")
            .filter { $0 != "." }
            .map { $0.lowercased() }
    }

    private static func isPrefix(_ prefix: [String], of value: [String]) -> Bool {
        value.count >= prefix.count && value.prefix(prefix.count).elementsEqual(prefix)
    }

    private static func isDescendant(_ candidate: String, of root: String) -> Bool {
        let rootPath = (root as NSString).standardizingPath
        let candidatePath = (candidate as NSString).standardizingPath
        return isContained(candidatePath, by: rootPath, allowingRoot: false)
    }

    private static func isContained(
        _ candidatePath: String,
        by rootPath: String,
        allowingRoot: Bool
    ) -> Bool {
        let rootComponents = URL(fileURLWithPath: rootPath).standardizedFileURL.pathComponents
        let candidateComponents = URL(fileURLWithPath: candidatePath)
            .standardizedFileURL
            .pathComponents

        guard candidateComponents.count >= rootComponents.count,
              candidateComponents.prefix(rootComponents.count).elementsEqual(rootComponents) else {
            return false
        }

        return allowingRoot || candidateComponents.count > rootComponents.count
    }
}
