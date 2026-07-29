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

    static func loadData(from url: URL) throws -> Data {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        let data = try handle.read(upToCount: maximumBytes + 1) ?? Data()
        guard data.count <= maximumBytes else {
            throw JSONDocumentLimitError()
        }
        return data
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
private struct UnsupportedJSONEncodingError: Error {}
private struct DuplicateJSONKeyError: Error {}
private struct MalformedJSONStructureError: Error {}

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
        try parseValue()
        skipWhitespace()
        guard index == bytes.count else {
            throw MalformedJSONStructureError()
        }
    }

    private mutating func parseValue() throws {
        skipWhitespace()
        guard let byte = currentByte else {
            throw MalformedJSONStructureError()
        }

        switch byte {
        case 0x7B:
            try parseObject()
        case 0x5B:
            try parseArray()
        case 0x22:
            _ = try parseString()
        default:
            try parseScalar()
        }
    }

    private mutating func parseObject() throws {
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
            try parseValue()
            skipWhitespace()

            if consumeIfPresent(0x7D) {
                return
            }
            try consume(0x2C)
        }
    }

    private mutating func parseArray() throws {
        try consume(0x5B)
        skipWhitespace()
        if consumeIfPresent(0x5D) {
            return
        }

        while true {
            try parseValue()
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
        let data = try JSONDocumentConstraints.loadData(from: url)
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
            var seenSourcePaths = Set<String>()
            for (index, sourcePath) in profile.sourcePaths.enumerated() {
                issues.append(
                    contentsOf: validateRelativePath(sourcePath, field: "sourcePaths[\(index)]")
                )

                if !seenSourcePaths.insert(sourcePath).inserted {
                    issues.append(
                        ValidationIssue(
                            code: "QC.PROFILE.DUPLICATE_SOURCE_PATH",
                            path: "sourcePaths[\(index)]",
                            message: "Source paths must be unique."
                        )
                    )
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

    static func resolvesWithinRepository(_ candidate: URL, root: URL) -> Bool {
        let resolvedRoot = root.resolvingSymlinksInPath().standardizedFileURL.path
        let resolvedCandidate = candidate.resolvingSymlinksInPath().standardizedFileURL.path
        return isContained(resolvedCandidate, by: resolvedRoot, allowingRoot: true)
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
