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

public enum ProfileLoader {
    public static func load(from url: URL) throws -> ProjectProfile {
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        return try JSONDecoder().decode(ProjectProfile.self, from: data)
    }
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

        return issues
    }

    static func resolve(relativePath: String, under root: URL) -> URL? {
        guard validateRelativePath(relativePath, field: "path").isEmpty else {
            return nil
        }

        let resolved = root.appendingPathComponent(relativePath).standardizedFileURL
        let rootPath = root.standardizedFileURL.path
        let resolvedPath = resolved.path

        guard resolvedPath == rootPath || resolvedPath.hasPrefix(rootPath + "/") else {
            return nil
        }

        return resolved
    }

    static func resolvesWithinRepository(_ candidate: URL, root: URL) -> Bool {
        let resolvedRoot = root.resolvingSymlinksInPath().standardizedFileURL.path
        let resolvedCandidate = candidate.resolvingSymlinksInPath().standardizedFileURL.path
        return resolvedCandidate == resolvedRoot
            || resolvedCandidate.hasPrefix(resolvedRoot + "/")
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

    private static func isDescendant(_ candidate: String, of root: String) -> Bool {
        let rootPath = (root as NSString).standardizingPath
        let candidatePath = (candidate as NSString).standardizingPath
        return candidatePath.hasPrefix(rootPath + "/")
    }
}
