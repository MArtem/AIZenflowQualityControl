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

private struct StaticPolicy: Decodable {
    let schemaVersion: Int
    let maximumFileBytes: Int
    let excludedDirectoryNames: [String]
    let forbiddenFileSuffixes: [String]

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

        if excludedDirectoryNames.contains(where: { $0.isEmpty || $0.contains("/") }) {
            checks.append(
                QualityCheck(
                    id: "QC.POLICY.INVALID_EXCLUDED_DIRECTORY",
                    status: .fail,
                    message: "Excluded directories must be non-empty single path components."
                )
            )
        }

        if forbiddenFileSuffixes.contains(where: { !$0.hasPrefix(".") || $0.count < 2 }) {
            checks.append(
                QualityCheck(
                    id: "QC.POLICY.INVALID_FILE_SUFFIX",
                    status: .fail,
                    message: "Forbidden file suffixes must start with a dot."
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
                let projectCheck = existenceCheck(
                    id: "QC.DOCTOR.PROJECT",
                    url: projectURL,
                    message: "Configured project or workspace exists.",
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

            checks.append(
                directoryCheck(
                    id: "QC.DOCTOR.SANDBOX_ROOT",
                    url: URL(fileURLWithPath: profile.sandbox.root),
                    message: "Configured sandbox root exists and is a directory."
                )
            )

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
                let data = try Data(contentsOf: policyURL, options: [.mappedIfSafe])
                policy = try JSONDecoder().decode(StaticPolicy.self, from: data)
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

            for sourcePath in profile.sourcePaths {
                guard let sourceURL = ProfileValidator.resolve(
                    relativePath: sourcePath,
                    under: repositoryRoot
                ) else {
                    checks.append(
                        QualityCheck(
                            id: "QC.STATIC.SOURCE_PATH",
                            status: .fail,
                            message: "Configured source path escapes the repository root.",
                            path: sourcePath
                        )
                    )
                    continue
                }

                let sourceCheck = directoryCheck(
                    id: "QC.STATIC.SOURCE_PATH",
                    url: sourceURL,
                    message: "Configured source path is scannable.",
                    relativePath: sourcePath
                )
                checks.append(sourceCheck)

                guard sourceCheck.status == .pass else {
                    continue
                }

                let boundaryCheck = repositoryBoundaryCheck(
                    id: "QC.STATIC.SOURCE_BOUNDARY",
                    url: sourceURL,
                    repositoryRoot: repositoryRoot,
                    relativePath: sourcePath
                )
                checks.append(boundaryCheck)

                guard boundaryCheck.status == .pass else {
                    continue
                }

                guard let enumerator = FileManager.default.enumerator(
                    at: sourceURL,
                    includingPropertiesForKeys: [
                        .isDirectoryKey,
                        .isRegularFileKey,
                        .isSymbolicLinkKey,
                        .fileSizeKey
                    ],
                    options: []
                ) else {
                    checks.append(
                        QualityCheck(
                            id: "QC.STATIC.ENUMERATION_BLOCKED",
                            status: .blocked,
                            message: "The configured source path could not be enumerated.",
                            path: sourcePath
                        )
                    )
                    continue
                }

                for case let fileURL as URL in enumerator {
                    let relativePath = relativePath(for: fileURL, root: repositoryRoot)

                    do {
                        let values = try fileURL.resourceValues(
                            forKeys: [
                                .isDirectoryKey,
                                .isRegularFileKey,
                                .isSymbolicLinkKey,
                                .fileSizeKey
                            ]
                        )

                        if values.isSymbolicLink == true {
                            if values.isDirectory == true {
                                enumerator.skipDescendants()
                            }
                            checks.append(
                                QualityCheck(
                                    id: "QC.STATIC.SYMLINK_REQUIRES_REVIEW",
                                    status: .blocked,
                                    message: "Symbolic links require explicit boundary review.",
                                    path: relativePath
                                )
                            )
                            continue
                        }

                        if values.isDirectory == true {
                            if policy.excludedDirectoryNames.contains(fileURL.lastPathComponent) {
                                enumerator.skipDescendants()
                            }
                            continue
                        }

                        guard values.isRegularFile == true else {
                            continue
                        }

                        scannedFileCount += 1

                        if let size = values.fileSize, size > policy.maximumFileBytes {
                            checks.append(
                                QualityCheck(
                                    id: "QC.STATIC.OVERSIZED_FILE",
                                    status: .fail,
                                    message: "File exceeds the configured maximum byte size.",
                                    path: relativePath
                                )
                            )
                        }

                        let lowercasedPath = fileURL.lastPathComponent.lowercased()
                        if policy.forbiddenFileSuffixes.contains(
                            where: { lowercasedPath.hasSuffix($0.lowercased()) }
                        ) {
                            checks.append(
                                QualityCheck(
                                    id: "QC.STATIC.FORBIDDEN_ARTIFACT",
                                    status: .fail,
                                    message: "Generated or release artifact is forbidden in source scope.",
                                    path: relativePath
                                )
                            )
                        }
                    } catch {
                        checks.append(
                            QualityCheck(
                                id: "QC.STATIC.METADATA_BLOCKED",
                                status: .blocked,
                                message: "File metadata could not be read.",
                                path: relativePath
                            )
                        )
                    }
                }
            }

            if !checks.contains(where: {
                $0.id.hasPrefix("QC.STATIC.") && $0.status != .pass
            }) {
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

    private static func existenceCheck(
        id: String,
        url: URL,
        message: String,
        relativePath: String? = nil
    ) -> QualityCheck {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return QualityCheck(
                id: id,
                status: .blocked,
                message: "Configured path does not exist.",
                path: relativePath
            )
        }

        return QualityCheck(id: id, status: .pass, message: message, path: relativePath)
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

        guard path.hasPrefix(rootPath + "/") else {
            return "<outside-repository>"
        }

        return String(path.dropFirst(rootPath.count + 1))
    }
}
