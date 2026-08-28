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
                "sandbox",
                "engine",
                "xcode",
                "applicability"
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

        if let engine = profile["engine"] as? [String: Any] {
            try rejectUnknownProperties(in: engine, allowed: ["version", "revision"])
        }

        if let xcode = profile["xcode"] as? [String: Any] {
            try rejectUnknownProperties(in: xcode, allowed: ["sourceMembership", "schemes"])
            if let membership = xcode["sourceMembership"] as? [String: Any] {
                try rejectUnknownProperties(in: membership, allowed: ["authority"])
            }
            if let schemes = xcode["schemes"] as? [[String: Any]] {
                for scheme in schemes {
                    try rejectUnknownProperties(
                        in: scheme,
                        allowed: ["name", "targets", "configurations", "destinations", "testPlans"]
                    )
                }
            }
        }

        if let applicability = profile["applicability"] as? [[String: Any]] {
            for decision in applicability {
                try rejectUnknownProperties(
                    in: decision,
                    allowed: ["capability", "status", "reason", "owner", "revisitCondition"]
                )
            }
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
    static let maximumSchemes = 32
    static let maximumSchemeValues = 64
    static let maximumIssues = 256
}

public enum ProfileValidator {
    public static func validate(_ profile: ProjectProfile) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []

        if ![1, 2].contains(profile.schemaVersion) {
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.UNSUPPORTED_SCHEMA",
                    path: "schemaVersion",
                    message: "Only project profile schemaVersion 1 or 2 is supported."
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

        issues.append(contentsOf: validateVersionedFields(profile))

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

        issues.append(contentsOf: validateSandboxPaths(profile))

        return boundedIssues(issues)
    }

    private static func validateVersionedFields(_ profile: ProjectProfile) -> [ValidationIssue] {
        switch profile.schemaVersion {
        case 1:
            var issues: [ValidationIssue] = []
            if profile.scheme?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false {
                issues.append(
                    ValidationIssue(
                        code: "QC.PROFILE.EMPTY_SCHEME",
                        path: "scheme",
                        message: "A schemaVersion 1 profile must provide one scheme."
                    )
                )
            }
            if profile.engine != nil || profile.xcode != nil || profile.applicability != nil {
                issues.append(
                    ValidationIssue(
                        code: "QC.PROFILE.VERSION_FIELD_MISMATCH",
                        path: "$",
                        message: "SchemaVersion 2 fields are forbidden in a schemaVersion 1 profile."
                    )
                )
            }
            return issues
        case 2:
            var issues: [ValidationIssue] = []
            if profile.scheme != nil {
                issues.append(
                    ValidationIssue(
                        code: "QC.PROFILE.VERSION_FIELD_MISMATCH",
                        path: "scheme",
                        message: "A schemaVersion 2 profile declares schemes only through xcode.schemes."
                    )
                )
            }
            issues.append(contentsOf: validateEnginePin(profile.engine))
            issues.append(contentsOf: validateXcodeConfiguration(profile.xcode))
            issues.append(contentsOf: validateApplicability(profile.applicability))
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.XCODE_GRAPH_RESOLUTION_REQUIRED",
                    path: "xcode.sourceMembership",
                    message: "SchemaVersion 2 remains blocked until authoritative Xcode graph resolution succeeds."
                )
            )
            return issues
        default:
            return []
        }
    }

    private static func validateEnginePin(_ engine: EnginePin?) -> [ValidationIssue] {
        guard let engine else {
            return [
                ValidationIssue(
                    code: "QC.PROFILE.MISSING_ENGINE_PIN",
                    path: "engine",
                    message: "A schemaVersion 2 profile must pin an engine version and revision."
                )
            ]
        }

        var issues: [ValidationIssue] = []
        if isBlank(engine.version) {
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.EMPTY_ENGINE_VERSION",
                    path: "engine.version",
                    message: "The pinned engine version must not be empty."
                )
            )
        }
        let revisionBytes = Array(engine.revision.utf8)
        if revisionBytes.count != 40
            || revisionBytes.contains(where: { !(48...57).contains($0) && !(97...102).contains($0) }) {
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.INVALID_ENGINE_REVISION",
                    path: "engine.revision",
                    message: "The pinned engine revision must be 40 lowercase hexadecimal characters."
                )
            )
        }
        return issues
    }

    private static func validateXcodeConfiguration(
        _ xcode: XcodeConfiguration?
    ) -> [ValidationIssue] {
        guard let xcode else {
            return [
                ValidationIssue(
                    code: "QC.PROFILE.MISSING_XCODE_CONFIGURATION",
                    path: "xcode",
                    message: "A schemaVersion 2 profile must declare its Xcode graph selection."
                )
            ]
        }

        var issues: [ValidationIssue] = []
        guard !xcode.schemes.isEmpty else {
            return [
                ValidationIssue(
                    code: "QC.PROFILE.EMPTY_SCHEMES",
                    path: "xcode.schemes",
                    message: "At least one shared Xcode scheme must be declared."
                )
            ]
        }
        if xcode.schemes.count > ProfileValidationLimits.maximumSchemes {
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.SCHEME_LIMIT",
                    path: "xcode.schemes",
                    message: "A profile may contain at most \(ProfileValidationLimits.maximumSchemes) schemes."
                )
            )
            return issues
        }

        var schemeNames = Set<String>()
        for (index, scheme) in xcode.schemes.enumerated() {
            let path = "xcode.schemes[\(index)]"
            if isBlank(scheme.name) || !schemeNames.insert(scheme.name).inserted {
                issues.append(
                    ValidationIssue(
                        code: "QC.PROFILE.INVALID_SCHEME",
                        path: "\(path).name",
                        message: "Scheme names must be non-empty and unique."
                    )
                )
            }
            issues.append(contentsOf: validateStringList(scheme.targets, path: "\(path).targets", allowsEmpty: false))
            issues.append(contentsOf: validateStringList(scheme.configurations, path: "\(path).configurations", allowsEmpty: false))
            issues.append(contentsOf: validateStringList(scheme.destinations, path: "\(path).destinations", allowsEmpty: false))
            issues.append(contentsOf: validateStringList(scheme.testPlans, path: "\(path).testPlans", allowsEmpty: true))
            for (testPlanIndex, testPlan) in scheme.testPlans.enumerated() {
                issues.append(contentsOf: validateRelativePath(
                    testPlan,
                    field: "\(path).testPlans[\(testPlanIndex)]"
                ))
            }
        }
        return issues
    }

    private static func validateApplicability(
        _ applicability: [CapabilityApplicability]?
    ) -> [ValidationIssue] {
        guard let applicability else {
            return [
                ValidationIssue(
                    code: "QC.PROFILE.MISSING_APPLICABILITY",
                    path: "applicability",
                    message: "A schemaVersion 2 profile must classify every governed capability."
                )
            ]
        }

        var issues: [ValidationIssue] = []
        var capabilities = Set<CapabilityID>()
        for (index, decision) in applicability.enumerated() {
            let path = "applicability[\(index)]"
            if !capabilities.insert(decision.capability).inserted {
                issues.append(
                    ValidationIssue(
                        code: "QC.PROFILE.DUPLICATE_APPLICABILITY",
                        path: "\(path).capability",
                        message: "Each governed capability must be classified exactly once."
                    )
                )
            }
            for (field, value) in [
                ("reason", decision.reason),
                ("owner", decision.owner),
                ("revisitCondition", decision.revisitCondition)
            ] where isBlank(value) {
                issues.append(
                    ValidationIssue(
                        code: "QC.PROFILE.EMPTY_APPLICABILITY_FIELD",
                        path: "\(path).\(field)",
                        message: "Applicability reason, owner, and revisit condition are mandatory."
                    )
                )
            }
        }

        let missing = Set(CapabilityID.allCases).subtracting(capabilities)
        if !missing.isEmpty {
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.INCOMPLETE_APPLICABILITY",
                    path: "applicability",
                    message: "Every governed capability must be classified exactly once."
                )
            )
        }
        return issues
    }

    private static func validateStringList(
        _ values: [String],
        path: String,
        allowsEmpty: Bool
    ) -> [ValidationIssue] {
        if values.isEmpty && !allowsEmpty {
            return [
                ValidationIssue(
                    code: "QC.PROFILE.EMPTY_XCODE_SELECTION",
                    path: path,
                    message: "This Xcode selection must not be empty."
                )
            ]
        }
        if values.count > ProfileValidationLimits.maximumSchemeValues {
            return [
                ValidationIssue(
                    code: "QC.PROFILE.XCODE_SELECTION_LIMIT",
                    path: path,
                    message: "An Xcode selection may contain at most \(ProfileValidationLimits.maximumSchemeValues) values."
                )
            ]
        }

        var accepted = Set<String>()
        var issues: [ValidationIssue] = []
        for (index, value) in values.enumerated()
            where isBlank(value) || !accepted.insert(value).inserted {
            issues.append(
                ValidationIssue(
                    code: "QC.PROFILE.INVALID_XCODE_SELECTION",
                    path: "\(path)[\(index)]",
                    message: "Xcode selection values must be non-empty and unique."
                )
            )
        }
        return issues
    }

    private static func isBlank(_ value: String) -> Bool {
        value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private static func validateSandboxPaths(_ profile: ProjectProfile) -> [ValidationIssue] {
        switch profile.schemaVersion {
        case 2:
            var issues = validatePortableSandboxPath(
                profile.sandbox.root,
                field: "sandbox.root"
            )
            issues.append(contentsOf: validatePortableSandboxPath(
                profile.sandbox.cache,
                field: "sandbox.cache"
            ))
            if issues.isEmpty,
               !isDescendant(profile.sandbox.cache, of: profile.sandbox.root) {
                issues.append(
                    ValidationIssue(
                        code: "QC.PROFILE.CACHE_OUTSIDE_SANDBOX",
                        path: "sandbox.cache",
                        message: "The cache path must remain strictly below the configured sandbox root."
                    )
                )
            }
            return issues
        default:
            var issues: [ValidationIssue] = []
            if !isAbsolute(profile.sandbox.root) {
                issues.append(
                    ValidationIssue(
                        code: "QC.PROFILE.SANDBOX_ROOT_NOT_ABSOLUTE",
                        path: "sandbox.root",
                        message: "A schemaVersion 1 sandbox root must be an absolute path."
                    )
                )
            }
            if !isAbsolute(profile.sandbox.cache) {
                issues.append(
                    ValidationIssue(
                        code: "QC.PROFILE.CACHE_NOT_ABSOLUTE",
                        path: "sandbox.cache",
                        message: "A schemaVersion 1 cache path must be an absolute path."
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
            return issues
        }
    }

    private static func validatePortableSandboxPath(
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
                    code: "QC.PROFILE.SANDBOX_PATH_NOT_RELATIVE",
                    path: field,
                    message: "A schemaVersion 2 sandbox path must be relative to the repository root."
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

        guard value != ".",
              !components.contains(where: { $0.isEmpty || $0 == "." }),
              (value as NSString).standardizingPath == value else {
            return [
                ValidationIssue(
                    code: "QC.PROFILE.NON_NORMALIZED_SANDBOX_PATH",
                    path: field,
                    message: "A schemaVersion 2 sandbox path must be a normalized repository-relative path."
                )
            ]
        }
        return []
    }

    static func resolveSandboxPaths(
        for profile: ProjectProfile,
        under repositoryRoot: URL
    ) -> (root: URL, cache: URL)? {
        switch profile.schemaVersion {
        case 1:
            guard isAbsolute(profile.sandbox.root), isAbsolute(profile.sandbox.cache) else {
                return nil
            }
            return (
                URL(fileURLWithPath: profile.sandbox.root, isDirectory: true),
                URL(fileURLWithPath: profile.sandbox.cache, isDirectory: true)
            )
        case 2:
            guard validatePortableSandboxPath(
                      profile.sandbox.root,
                      field: "sandbox.root"
                  ).isEmpty,
                  validatePortableSandboxPath(
                      profile.sandbox.cache,
                      field: "sandbox.cache"
                  ).isEmpty,
                  let root = resolve(relativePath: profile.sandbox.root, under: repositoryRoot),
                  let cache = resolve(relativePath: profile.sandbox.cache, under: repositoryRoot),
                  isDescendant(cache.path, of: root.path) else {
                return nil
            }
            return (root, cache)
        default:
            return nil
        }
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
