import Foundation

public enum QualityStatus: String, Codable, Sendable {
    case pass = "PASS"
    case fail = "FAIL"
    case blocked = "BLOCKED"
}

public struct QualityCheck: Codable, Sendable {
    public let id: String
    public let status: QualityStatus
    public let message: String
    public let path: String?

    public init(id: String, status: QualityStatus, message: String, path: String? = nil) {
        self.id = id
        self.status = status
        self.message = message
        self.path = path
    }
}

public struct QualityReport: Codable, Sendable {
    public let schemaVersion: Int
    public let command: String
    public let status: QualityStatus
    public let checks: [QualityCheck]

    public init(command: String, checks: [QualityCheck]) {
        self.schemaVersion = 1
        self.command = command

        guard !checks.isEmpty else {
            self.checks = [
                QualityCheck(
                    id: "QC.REPORT.NO_CHECKS",
                    status: .blocked,
                    message: "A quality report cannot pass without executed checks."
                )
            ]
            self.status = .blocked
            return
        }

        self.checks = checks

        if checks.contains(where: { $0.status == .fail }) {
            self.status = .fail
        } else if checks.contains(where: { $0.status == .blocked }) {
            self.status = .blocked
        } else {
            self.status = .pass
        }
    }
}

private struct StaticPolicyDocument: Decodable {
    let schemaVersion: Int
    let maximumFileBytes: Int
    let excludedDirectoryNames: [String]
    let forbiddenFileSuffixes: [String]
}

private struct StaticPolicy {
    let schemaVersion: Int
    let maximumFileBytes: Int
    let excludedDirectoryNames: [String]
    let forbiddenFileSuffixes: [String]
    private let excludedDirectoryNameSet: Set<String>
    private let normalizedForbiddenFileSuffixes: [String]

    static func decode(from data: Data) throws -> StaticPolicy {
        try JSONDocumentConstraints.rejectDuplicateObjectKeys(in: data)

        if let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
            let allowedProperties: Set<String> = [
                "schemaVersion",
                "maximumFileBytes",
                "excludedDirectoryNames",
                "forbiddenFileSuffixes"
            ]

            guard Set(object.keys).isSubset(of: allowedProperties) else {
                throw UnknownStaticPolicyPropertyError()
            }
        }

        let document = try JSONDecoder().decode(StaticPolicyDocument.self, from: data)
        return StaticPolicy(
            schemaVersion: document.schemaVersion,
            maximumFileBytes: document.maximumFileBytes,
            excludedDirectoryNames: document.excludedDirectoryNames,
            forbiddenFileSuffixes: document.forbiddenFileSuffixes,
            excludedDirectoryNameSet: Set(document.excludedDirectoryNames),
            normalizedForbiddenFileSuffixes: document.forbiddenFileSuffixes.map {
                $0.lowercased()
            }
        )
    }

    func matchesForbiddenSuffix(_ pathComponent: String) -> Bool {
        let lowercasedComponent = pathComponent.lowercased()
        return normalizedForbiddenFileSuffixes.contains {
            lowercasedComponent.hasSuffix($0)
        }
    }

    func excludesDirectory(_ pathComponent: String) -> Bool {
        excludedDirectoryNameSet.contains(pathComponent)
    }

    func validationChecks() -> [QualityCheck] {
        var checks: [QualityCheck] = []

        if schemaVersion != 1 {
            checks.append(
                QualityCheck(
                    id: "QC.POLICY.UNSUPPORTED_SCHEMA",
                    status: .fail,
                    message: "Only static policy schemaVersion 1 is supported."
                )
            )
        }

        if maximumFileBytes <= 0 {
            checks.append(
                QualityCheck(
                    id: "QC.POLICY.INVALID_FILE_LIMIT",
                    status: .fail,
                    message: "maximumFileBytes must be greater than zero."
                )
            )
        }

        if excludedDirectoryNames.count > StaticPolicyLimits.maximumListItems
            || forbiddenFileSuffixes.count > StaticPolicyLimits.maximumListItems {
            checks.append(
                QualityCheck(
                    id: "QC.POLICY.LIST_LIMIT",
                    status: .fail,
                    message: "Static policy lists may contain at most \(StaticPolicyLimits.maximumListItems) items each."
                )
            )
        }

        if excludedDirectoryNames.contains(where: { $0.isEmpty || $0.contains("/") }) {
            checks.append(
                QualityCheck(
                    id: "QC.POLICY.INVALID_EXCLUDED_DIRECTORY",
                    status: .fail,
                    message: "Excluded directories must be non-empty single path components."
                )
            )
        }

        if forbiddenFileSuffixes.contains(where: {
            !$0.hasPrefix(".") || $0.count < 2 || $0.contains("/")
        }) {
            checks.append(
                QualityCheck(
                    id: "QC.POLICY.INVALID_FILE_SUFFIX",
                    status: .fail,
                    message: "Forbidden file suffixes must be single path components starting with a dot."
                )
            )
        }

        if Set(excludedDirectoryNames).count != excludedDirectoryNames.count {
            checks.append(
                QualityCheck(
                    id: "QC.POLICY.DUPLICATE_EXCLUDED_DIRECTORY",
                    status: .fail,
                    message: "Excluded directory names must be unique."
                )
            )
        }

        if Set(normalizedForbiddenFileSuffixes).count
            != normalizedForbiddenFileSuffixes.count {
            checks.append(
                QualityCheck(
                    id: "QC.POLICY.DUPLICATE_FILE_SUFFIX",
                    status: .fail,
                    message: "Forbidden file suffixes must be unique ignoring case."
                )
            )
        }

        if checks.isEmpty {
            checks.append(
                QualityCheck(
                    id: "QC.POLICY.CONTRACT",
                    status: .pass,
                    message: "Static policy contract is valid."
                )
            )
        }

        return checks
    }
}

private struct UnknownStaticPolicyPropertyError: Error {}

private enum StaticPolicyLimits {
    static let maximumListItems = 256
}

private enum StaticScanLimits {
    static let maximumEntries = 100_000
    static let maximumFindings = 1_000
}

private struct StaticSourceScope {
    let configuredPath: String
    let url: URL
    let resolvedIdentityComponents: [String]
}

private enum StaticEntryMetadata {
    case available(URLResourceValues)
    case unavailable
}

private struct StaticScanEntry {
    let url: URL
    let relativePath: String
    let metadata: StaticEntryMetadata
}

private enum ProfileLoadResult {
    case success(ProjectProfile)
    case failure(QualityCheck)
}

public enum QualityCommands {
    public static func validateProfile(at profileURL: URL) -> QualityReport {
        switch loadProfile(at: profileURL) {
        case let .failure(check):
            return QualityReport(command: "validate-profile", checks: [check])
        case let .success(profile):
            let issues = ProfileValidator.validate(profile)
            let checks = checks(for: issues)

            return QualityReport(
                command: "validate-profile",
                checks: checks.isEmpty
                    ? [
                        QualityCheck(
                            id: "QC.PROFILE.CONTRACT",
                            status: .pass,
                            message: "Project profile contract is valid."
                        )
                    ]
                    : checks
            )
        }
    }

    public static func doctor(profileURL: URL, repositoryRoot: URL) -> QualityReport {
        switch loadProfile(at: profileURL) {
        case let .failure(check):
            return QualityReport(command: "doctor", checks: [check])
        case let .success(profile):
            let issues = ProfileValidator.validate(profile)
            guard issues.isEmpty else {
                return QualityReport(command: "doctor", checks: checks(for: issues))
            }

            var checks: [QualityCheck] = [
                QualityCheck(
                    id: "QC.PROFILE.CONTRACT",
                    status: .pass,
                    message: "Project profile contract is valid."
                )
            ]

            checks.append(
                directoryCheck(
                    id: "QC.DOCTOR.REPOSITORY_ROOT",
                    url: repositoryRoot,
                    message: "Repository root exists and is a directory."
                )
            )

            if let projectURL = ProfileValidator.resolve(
                relativePath: profile.project.path,
                under: repositoryRoot
            ) {
                let projectCheck = directoryCheck(
                    id: "QC.DOCTOR.PROJECT",
                    url: projectURL,
                    message: "Configured project or workspace exists and is a directory.",
                    relativePath: profile.project.path
                )
                checks.append(projectCheck)

                if projectCheck.status == .pass {
                    checks.append(
                        repositoryBoundaryCheck(
                            id: "QC.DOCTOR.PROJECT_BOUNDARY",
                            url: projectURL,
                            repositoryRoot: repositoryRoot,
                            relativePath: profile.project.path
                        )
                    )
                }
            } else {
                checks.append(
                    QualityCheck(
                        id: "QC.DOCTOR.PROJECT_PATH",
                        status: .fail,
                        message: "Configured project path escapes the repository root."
                    )
                )
            }

            for sourcePath in profile.sourcePaths {
                guard let sourceURL = ProfileValidator.resolve(
                    relativePath: sourcePath,
                    under: repositoryRoot
                ) else {
                    checks.append(
                        QualityCheck(
                            id: "QC.DOCTOR.SOURCE_PATH",
                            status: .fail,
                            message: "Configured source path escapes the repository root.",
                            path: sourcePath
                        )
                    )
                    continue
                }

                let sourceCheck = directoryCheck(
                    id: "QC.DOCTOR.SOURCE_PATH",
                    url: sourceURL,
                    message: "Configured source path exists and is a directory.",
                    relativePath: sourcePath
                )
                checks.append(sourceCheck)

                if sourceCheck.status == .pass {
                    checks.append(
                        repositoryBoundaryCheck(
                            id: "QC.DOCTOR.SOURCE_BOUNDARY",
                            url: sourceURL,
                            repositoryRoot: repositoryRoot,
                            relativePath: sourcePath
                        )
                    )
                }
            }

            let sandboxRootURL = URL(fileURLWithPath: profile.sandbox.root)
            let sandboxRootCheck = directoryCheck(
                id: "QC.DOCTOR.SANDBOX_ROOT",
                url: sandboxRootURL,
                message: "Configured sandbox root exists and is a directory.",
                relativePath: profile.sandbox.root
            )
            checks.append(sandboxRootCheck)

            let sandboxCacheURL = URL(fileURLWithPath: profile.sandbox.cache)
            let sandboxCacheCheck = directoryCheck(
                id: "QC.DOCTOR.SANDBOX_CACHE",
                url: sandboxCacheURL,
                message: "Configured sandbox cache exists and is a directory.",
                relativePath: profile.sandbox.cache
            )
            checks.append(sandboxCacheCheck)

            if sandboxRootCheck.status == .pass, sandboxCacheCheck.status == .pass {
                let cacheRemainsInsideSandbox = ProfileValidator.resolvesWithinRepository(
                    sandboxCacheURL,
                    root: sandboxRootURL,
                    allowingRoot: false
                )
                checks.append(
                    QualityCheck(
                        id: "QC.DOCTOR.SANDBOX_CACHE_BOUNDARY",
                        status: cacheRemainsInsideSandbox ? .pass : .fail,
                        message: cacheRemainsInsideSandbox
                            ? "Resolved sandbox cache remains strictly below the sandbox root."
                            : "Resolved sandbox cache must remain strictly below the sandbox root.",
                        path: profile.sandbox.cache
                    )
                )
            }

            return QualityReport(command: "doctor", checks: checks)
        }
    }

    public static func staticScan(
        profileURL: URL,
        policyURL: URL,
        repositoryRoot: URL
    ) -> QualityReport {
        switch loadProfile(at: profileURL) {
        case let .failure(check):
            return QualityReport(command: "static", checks: [check])
        case let .success(profile):
            let profileIssues = ProfileValidator.validate(profile)
            guard profileIssues.isEmpty else {
                return QualityReport(command: "static", checks: checks(for: profileIssues))
            }

            let policy: StaticPolicy
            do {
                let data = try JSONDocumentConstraints.loadData(from: policyURL)
                policy = try StaticPolicy.decode(from: data)
            } catch {
                return QualityReport(
                    command: "static",
                    checks: [
                        QualityCheck(
                            id: "QC.POLICY.UNREADABLE",
                            status: .fail,
                            message: "Static policy could not be decoded."
                        )
                    ]
                )
            }

            let policyChecks = policy.validationChecks()
            guard !policyChecks.contains(where: { $0.status != .pass }) else {
                return QualityReport(command: "static", checks: policyChecks)
            }

            var checks: [QualityCheck] = [
                QualityCheck(
                    id: "QC.PROFILE.CONTRACT",
                    status: .pass,
                    message: "Project profile contract is valid."
                )
            ] + policyChecks

            let rootCheck = directoryCheck(
                id: "QC.STATIC.REPOSITORY_ROOT",
                url: repositoryRoot,
                message: "Repository root exists and is a directory."
            )
            checks.append(rootCheck)

            guard rootCheck.status == .pass else {
                return QualityReport(command: "static", checks: checks)
            }

            var scannedFileCount = 0
            var scannedEntryCount = 0
            var reportedFindingCount = 0
            var scanLimitMessage: String?

            func appendStaticCheck(_ check: QualityCheck) -> Bool {
                checks.append(check)

                guard check.status != .pass else {
                    return true
                }

                reportedFindingCount += 1
                if reportedFindingCount >= StaticScanLimits.maximumFindings {
                    scanLimitMessage = "Static scan stopped after reaching the finding limit of \(StaticScanLimits.maximumFindings)."
                    return false
                }

                return true
            }

            var sourceScopes: [StaticSourceScope] = []
            let orderedSourcePaths = profile.sourcePaths.sorted {
                let lhs = ($0 as NSString).standardizingPath.lowercased()
                let rhs = ($1 as NSString).standardizingPath.lowercased()
                return lhs == rhs ? $0 < $1 : lhs < rhs
            }

            sourceValidationLoop: for sourcePath in orderedSourcePaths {
                guard let sourceURL = ProfileValidator.resolve(
                    relativePath: sourcePath,
                    under: repositoryRoot
                ) else {
                    guard appendStaticCheck(
                        QualityCheck(
                            id: "QC.STATIC.SOURCE_PATH",
                            status: .fail,
                            message: "Configured source path escapes the repository root.",
                            path: sourcePath
                        )
                    ) else {
                        break sourceValidationLoop
                    }
                    continue
                }

                let sourceCheck = directoryCheck(
                    id: "QC.STATIC.SOURCE_PATH",
                    url: sourceURL,
                    message: "Configured source path is scannable.",
                    relativePath: sourcePath
                )
                guard appendStaticCheck(sourceCheck) else {
                    break sourceValidationLoop
                }

                guard sourceCheck.status == .pass else {
                    continue
                }

                let boundaryCheck = repositoryBoundaryCheck(
                    id: "QC.STATIC.SOURCE_BOUNDARY",
                    url: sourceURL,
                    repositoryRoot: repositoryRoot,
                    relativePath: sourcePath
                )
                guard appendStaticCheck(boundaryCheck) else {
                    break sourceValidationLoop
                }

                guard boundaryCheck.status == .pass else {
                    continue
                }

                if policy.matchesForbiddenSuffix(sourceURL.lastPathComponent) {
                    guard appendStaticCheck(
                        QualityCheck(
                            id: "QC.STATIC.FORBIDDEN_ARTIFACT",
                            status: .fail,
                            message: "The configured source root is a forbidden generated or release artifact.",
                            path: sourcePath
                        )
                    ) else {
                        break sourceValidationLoop
                    }
                    continue
                }

                let resolvedIdentityComponents = sourceURL
                    .resolvingSymlinksInPath()
                    .standardizedFileURL
                    .pathComponents
                    .map { $0.lowercased() }

                if let overlappingScope = sourceScopes.first(where: {
                    components($0.resolvedIdentityComponents, overlap: resolvedIdentityComponents)
                }) {
                    guard appendStaticCheck(
                        QualityCheck(
                            id: "QC.STATIC.OVERLAPPING_SOURCE_SCOPE",
                            status: .fail,
                            message: "Resolved source scopes must not duplicate or overlap another scope (\(overlappingScope.configuredPath)).",
                            path: sourcePath
                        )
                    ) else {
                        break sourceValidationLoop
                    }
                    continue
                }

                sourceScopes.append(
                    StaticSourceScope(
                        configuredPath: sourcePath,
                        url: sourceURL,
                        resolvedIdentityComponents: resolvedIdentityComponents
                    )
                )
            }

            let hasSourceValidationProblem = checks.contains(where: {
                $0.id.hasPrefix("QC.STATIC.") && $0.status != .pass
            })
            guard !hasSourceValidationProblem else {
                return QualityReport(command: "static", checks: checks)
            }

            sourceScopes.sort {
                let lhs = $0.resolvedIdentityComponents.joined(separator: "/")
                let rhs = $1.resolvedIdentityComponents.joined(separator: "/")
                return lhs == rhs ? $0.configuredPath < $1.configuredPath : lhs < rhs
            }

            sourceLoop: for sourceScope in sourceScopes {
                let sourceURL = sourceScope.url
                let sourcePath = sourceScope.configuredPath

                var enumerationWasBlocked = false
                guard let enumerator = FileManager.default.enumerator(
                    at: sourceURL,
                    includingPropertiesForKeys: [
                        .isDirectoryKey,
                        .isRegularFileKey,
                        .isSymbolicLinkKey,
                        .fileSizeKey
                    ],
                    options: [],
                    errorHandler: { _, _ in
                        enumerationWasBlocked = true
                        return false
                    }
                ) else {
                    guard appendStaticCheck(
                        QualityCheck(
                            id: "QC.STATIC.ENUMERATION_BLOCKED",
                            status: .blocked,
                            message: "The configured source path could not be enumerated.",
                            path: sourcePath
                        )
                    ) else {
                        break sourceLoop
                    }
                    continue
                }

                var entries: [StaticScanEntry] = []
                entryCollectionLoop: for case let fileURL as URL in enumerator {
                    guard scannedEntryCount < StaticScanLimits.maximumEntries else {
                        scanLimitMessage = "Static scan stopped after reaching the entry limit of \(StaticScanLimits.maximumEntries)."
                        break entryCollectionLoop
                    }
                    scannedEntryCount += 1

                    let entryRelativePath = relativePath(for: fileURL, root: repositoryRoot)

                    do {
                        let values = try fileURL.resourceValues(
                            forKeys: [
                                .isDirectoryKey,
                                .isRegularFileKey,
                                .isSymbolicLinkKey,
                                .fileSizeKey
                            ]
                        )

                        if values.isDirectory == true {
                            let isForbiddenDirectory = policy.matchesForbiddenSuffix(
                                fileURL.lastPathComponent
                            )
                            if isForbiddenDirectory
                                || policy.excludesDirectory(fileURL.lastPathComponent)
                                || values.isSymbolicLink == true {
                                enumerator.skipDescendants()
                            }

                            if policy.excludesDirectory(fileURL.lastPathComponent),
                               !isForbiddenDirectory,
                               values.isSymbolicLink != nil {
                                continue
                            }
                        }

                        entries.append(
                            StaticScanEntry(
                                url: fileURL,
                                relativePath: entryRelativePath,
                                metadata: .available(values)
                            )
                        )
                    } catch {
                        entries.append(
                            StaticScanEntry(
                                url: fileURL,
                                relativePath: entryRelativePath,
                                metadata: .unavailable
                            )
                        )
                    }
                }

                if enumerationWasBlocked {
                    guard appendStaticCheck(
                        QualityCheck(
                            id: "QC.STATIC.ENUMERATION_BLOCKED",
                            status: .blocked,
                            message: "Directory enumeration stopped because an entry could not be read.",
                            path: sourcePath
                        )
                    ) else {
                        break sourceLoop
                    }
                    continue
                }

                if scanLimitMessage != nil {
                    break sourceLoop
                }

                entries.sort {
                    $0.relativePath == $1.relativePath
                        ? $0.url.path < $1.url.path
                        : $0.relativePath < $1.relativePath
                }

                entryProcessingLoop: for entry in entries {
                    if policy.matchesForbiddenSuffix(entry.url.lastPathComponent) {
                        guard appendStaticCheck(
                            QualityCheck(
                                id: "QC.STATIC.FORBIDDEN_ARTIFACT",
                                status: .fail,
                                message: "Generated or release artifact is forbidden in source scope.",
                                path: entry.relativePath
                            )
                        ) else {
                            break entryProcessingLoop
                        }
                    }

                    guard case let .available(values) = entry.metadata else {
                        guard appendStaticCheck(
                            QualityCheck(
                                id: "QC.STATIC.METADATA_BLOCKED",
                                status: .blocked,
                                message: "Entry metadata could not be read.",
                                path: entry.relativePath
                            )
                        ) else {
                            break entryProcessingLoop
                        }
                        continue
                    }

                    guard let isSymbolicLink = values.isSymbolicLink else {
                        guard appendStaticCheck(
                            QualityCheck(
                                id: "QC.STATIC.METADATA_BLOCKED",
                                status: .blocked,
                                message: "Entry symbolic-link metadata is unavailable.",
                                path: entry.relativePath
                            )
                        ) else {
                            break entryProcessingLoop
                        }
                        continue
                    }

                    if isSymbolicLink {
                        guard appendStaticCheck(
                            QualityCheck(
                                id: "QC.STATIC.SYMLINK_REQUIRES_REVIEW",
                                status: .blocked,
                                message: "Symbolic links require explicit boundary review.",
                                path: entry.relativePath
                            )
                        ) else {
                            break entryProcessingLoop
                        }
                        continue
                    }

                    guard let isDirectory = values.isDirectory,
                          let isRegularFile = values.isRegularFile else {
                        guard appendStaticCheck(
                            QualityCheck(
                                id: "QC.STATIC.METADATA_BLOCKED",
                                status: .blocked,
                                message: "Entry type metadata is unavailable.",
                                path: entry.relativePath
                            )
                        ) else {
                            break entryProcessingLoop
                        }
                        continue
                    }

                    if isDirectory || !isRegularFile {
                        continue
                    }

                    scannedFileCount += 1

                    guard let size = values.fileSize else {
                        guard appendStaticCheck(
                            QualityCheck(
                                id: "QC.STATIC.METADATA_BLOCKED",
                                status: .blocked,
                                message: "Regular file size metadata is unavailable.",
                                path: entry.relativePath
                            )
                        ) else {
                            break entryProcessingLoop
                        }
                        continue
                    }

                    if size > policy.maximumFileBytes {
                        guard appendStaticCheck(
                            QualityCheck(
                                id: "QC.STATIC.OVERSIZED_FILE",
                                status: .fail,
                                message: "File exceeds the configured maximum byte size.",
                                path: entry.relativePath
                            )
                        ) else {
                            break entryProcessingLoop
                        }
                    }
                }

                if scanLimitMessage != nil {
                    break sourceLoop
                }
            }

            if let scanLimitMessage {
                checks.append(
                    QualityCheck(
                        id: "QC.STATIC.SCAN_LIMIT_REACHED",
                        status: .blocked,
                        message: scanLimitMessage
                    )
                )
            }

            let hasStaticProblem = checks.contains(where: {
                $0.id.hasPrefix("QC.STATIC.") && $0.status != .pass
            })

            if scannedFileCount == 0, !hasStaticProblem {
                checks.append(
                    QualityCheck(
                        id: "QC.STATIC.NO_FILES_SCANNED",
                        status: .blocked,
                        message: "Static scan inspected zero regular files."
                    )
                )
            } else if !hasStaticProblem {
                checks.append(
                    QualityCheck(
                        id: "QC.STATIC.SCAN",
                        status: .pass,
                        message: "Static scan completed for \(scannedFileCount) regular files."
                    )
                )
            }

            return QualityReport(command: "static", checks: checks)
        }
    }

    public static func blockedUsage(command: String, message: String) -> QualityReport {
        QualityReport(
            command: command,
            checks: [
                QualityCheck(
                    id: "QC.CLI.INVALID_ARGUMENTS",
                    status: .blocked,
                    message: message
                )
            ]
        )
    }

    private static func loadProfile(
        at url: URL
    ) -> ProfileLoadResult {
        do {
            return .success(try ProfileLoader.load(from: url))
        } catch {
            return .failure(
                QualityCheck(
                    id: "QC.PROFILE.UNREADABLE",
                    status: .fail,
                    message: "Project profile could not be decoded."
                )
            )
        }
    }

    private static func checks(for issues: [ValidationIssue]) -> [QualityCheck] {
        issues.map {
            QualityCheck(
                id: $0.code,
                status: .fail,
                message: $0.message,
                path: $0.path
            )
        }
    }

    private static func directoryCheck(
        id: String,
        url: URL,
        message: String,
        relativePath: String? = nil
    ) -> QualityCheck {
        var isDirectory: ObjCBool = false
        let exists = FileManager.default.fileExists(
            atPath: url.path,
            isDirectory: &isDirectory
        )

        guard exists, isDirectory.boolValue else {
            return QualityCheck(
                id: id,
                status: .blocked,
                message: "Configured directory does not exist or is not a directory.",
                path: relativePath
            )
        }

        return QualityCheck(id: id, status: .pass, message: message, path: relativePath)
    }

    private static func repositoryBoundaryCheck(
        id: String,
        url: URL,
        repositoryRoot: URL,
        relativePath: String
    ) -> QualityCheck {
        guard ProfileValidator.resolvesWithinRepository(url, root: repositoryRoot) else {
            return QualityCheck(
                id: id,
                status: .fail,
                message: "Resolved path escapes the repository root through a symbolic link.",
                path: relativePath
            )
        }

        return QualityCheck(
            id: id,
            status: .pass,
            message: "Resolved path remains inside the repository root.",
            path: relativePath
        )
    }

    private static func relativePath(for url: URL, root: URL) -> String {
        let rootPath = root.standardizedFileURL.path
        let path = url.standardizedFileURL.path

        if path == rootPath {
            return "."
        }

        if rootPath == "/", path.hasPrefix("/") {
            return String(path.dropFirst())
        }

        guard path.hasPrefix(rootPath + "/") else {
            return "<outside-repository>"
        }

        return String(path.dropFirst(rootPath.count + 1))
    }

    private static func components(_ lhs: [String], overlap rhs: [String]) -> Bool {
        let shorterCount = min(lhs.count, rhs.count)
        return lhs.prefix(shorterCount).elementsEqual(rhs.prefix(shorterCount))
    }
}
