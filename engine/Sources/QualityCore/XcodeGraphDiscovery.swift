import Darwin
import Foundation

enum XcodeGraphDiscovery {
    private static let maximumInvocations = 64
    private static let maximumOutputBytes = 4 * 1_024 * 1_024
    private static let invocationTimeoutSeconds: TimeInterval = 20
    private static let totalTimeoutSeconds: TimeInterval = 120

    static func checks(
        profile: ProjectProfile,
        repositoryRoot: URL
    ) -> [QualityCheck] {
        guard let sandboxPaths = ProfileValidator.resolveSandboxPaths(
                  for: profile,
                  under: repositoryRoot
              ),
              profile.schemaVersion != 2 || ProfileValidator.resolvesWithinRepository(
                  sandboxPaths.root,
                  root: repositoryRoot,
                  allowingRoot: false
              ),
              let paths = prepareCachePaths(
                  cacheRoot: sandboxPaths.cache,
                  sandboxRoot: sandboxPaths.root
              ) else {
            return [
                QualityCheck(
                    id: "QC.DOCTOR.XCODE_CACHE_BOUNDARY",
                    status: .blocked,
                    message: "Xcode discovery cache paths could not be prepared inside the configured sandbox."
                )
            ]
        }
        return checks(
            profile: profile,
            repositoryRoot: repositoryRoot,
            paths: paths,
            execute: run,
            startedAt: DispatchTime.now().uptimeNanoseconds
        )
    }

    static func checks(
        profile: ProjectProfile,
        repositoryRoot: URL,
        paths: XcodeGraphCachePaths,
        execute: XcodeGraphToolRunner,
        startedAt: UInt64
    ) -> [QualityCheck] {
        guard let xcode = profile.xcode else {
            return [
                QualityCheck(
                    id: "QC.DOCTOR.XCODE_CONFIGURATION",
                    status: .fail,
                    message: "The v2 profile does not contain an Xcode configuration."
                )
            ]
        }
        guard let projectURL = ProfileValidator.resolve(
            relativePath: profile.project.path,
            under: repositoryRoot
        ) else {
            return [
                QualityCheck(
                    id: "QC.DOCTOR.XCODE_PROJECT_BOUNDARY",
                    status: .fail,
                    message: "Xcode graph discovery requires a project inside the repository."
                )
            ]
        }

        let invocationCount = xcode.schemes.reduce(into: 0) { count, scheme in
            count += scheme.configurations.count * scheme.destinations.count
        }
        guard invocationCount > 0, invocationCount <= maximumInvocations else {
            return [
                QualityCheck(
                    id: "QC.DOCTOR.XCODE_MATRIX_LIMIT",
                    status: .blocked,
                    message: "The selected Xcode configuration/destination matrix exceeds the bounded discovery limit of \(maximumInvocations)."
                )
            ]
        }

        let baseArguments = projectArguments(profile: profile, projectURL: projectURL)
            + packageArguments(paths: paths)
        guard case let .success(inventoryData) = execute(
            baseArguments + ["-list", "-json"],
            repositoryRoot,
            paths.temporary,
            startedAt
        ), let inventory = decodeInventory(inventoryData, kind: profile.project.kind) else {
            return [
                QualityCheck(
                    id: "QC.DOCTOR.XCODE_INVENTORY",
                    status: .blocked,
                    message: "Xcode project inventory was unavailable, malformed, oversized, or timed out."
                )
            ]
        }

        let declaredSchemes = Set(xcode.schemes.map(\.name))
        let missingSchemes = declaredSchemes.subtracting(inventory.schemes)
        guard missingSchemes.isEmpty else {
            return [
                QualityCheck(
                    id: "QC.DOCTOR.XCODE_SCHEME_MISMATCH",
                    status: .fail,
                    message: "One or more profile schemes are absent from the selected Xcode container."
                )
            ]
        }

        let declaredConfigurations = Set(xcode.schemes.flatMap(\.configurations))
        if !inventory.configurations.isEmpty,
           !declaredConfigurations.isSubset(of: inventory.configurations) {
            return [
                QualityCheck(
                    id: "QC.DOCTOR.XCODE_CONFIGURATION_MISMATCH",
                    status: .fail,
                    message: "One or more profile configurations are absent from the selected Xcode project."
                )
            ]
        }

        let declaredTargets = Set(xcode.schemes.flatMap(\.targets))
        if !inventory.targets.isEmpty, !declaredTargets.isSubset(of: inventory.targets) {
            return [
                QualityCheck(
                    id: "QC.DOCTOR.XCODE_TARGET_MISMATCH",
                    status: .fail,
                    message: "One or more profile targets are absent from the selected Xcode project."
                )
            ]
        }

        for scheme in xcode.schemes {
            let declaredSchemeTargets = Set(scheme.targets)
            for configuration in scheme.configurations {
                for destination in scheme.destinations {
                    let arguments = baseArguments + [
                        "-scheme", scheme.name,
                        "-configuration", configuration,
                        "-destination", destination,
                        "build",
                        "-showBuildSettings", "-json",
                        "-derivedDataPath", paths.derivedData.path
                    ]
                    guard case let .success(settingsData) = execute(
                        arguments,
                        repositoryRoot,
                        paths.temporary,
                        startedAt
                    ), let settings = decodeBuildSettings(settingsData), !settings.isEmpty else {
                        return [
                            QualityCheck(
                                id: "QC.DOCTOR.XCODE_EFFECTIVE_SETTINGS",
                                status: .blocked,
                                message: "Effective Xcode settings were unavailable, malformed, oversized, or timed out for a selected matrix entry."
                            )
                        ]
                    }

                    let observedSchemeTargets = Set(settings.map(\.target))
                    guard declaredSchemeTargets.isSubset(of: observedSchemeTargets),
                          settings.allSatisfy({ record in
                              record.buildSettings["CONFIGURATION"] == configuration
                                  && projectDirectoryIsInsideAllowedRoots(
                                      record.buildSettings["PROJECT_DIR"],
                                      repositoryRoot: repositoryRoot,
                                      sourcePackagesRoot: paths.sourcePackages
                                  )
                          }),
                          settings.filter({ declaredSchemeTargets.contains($0.target) })
                              .allSatisfy({ record in
                                  projectDirectoryIsInsideRepository(
                                      record.buildSettings["PROJECT_DIR"],
                                      repositoryRoot: repositoryRoot
                                  )
                              }) else {
                        return [
                            QualityCheck(
                                id: "QC.DOCTOR.XCODE_EFFECTIVE_SETTINGS_MISMATCH",
                                status: .fail,
                                message: "Effective Xcode settings do not match the declared scheme targets, configuration, or approved project boundaries."
                            )
                        ]
                    }
                }
            }
        }

        return [
            QualityCheck(
                id: "QC.DOCTOR.XCODE_GRAPH_SELECTION",
                status: .pass,
                message: "Declared schemes, targets, configurations, and destinations resolved through Xcode inventory and effective build settings."
            ),
            QualityCheck(
                id: "QC.DOCTOR.XCODE_SOURCE_MEMBERSHIP",
                status: .blocked,
                message: "Effective build settings do not prove compiled or shipped source membership; trusted build evidence is still required."
            )
        ]
    }

    private static func projectArguments(
        profile: ProjectProfile,
        projectURL: URL
    ) -> [String] {
        switch profile.project.kind {
        case .xcodeProject:
            return ["-project", projectURL.path]
        case .xcodeWorkspace:
            return ["-workspace", projectURL.path]
        }
    }

    private static func packageArguments(paths: XcodeGraphCachePaths) -> [String] {
        [
            "-disableAutomaticPackageResolution",
            "-onlyUsePackageVersionsFromResolvedFile",
            "-skipPackageUpdates",
            "-clonedSourcePackagesDirPath", paths.sourcePackages.path,
            "-packageCachePath", paths.packageCache.path
        ]
    }

    private static func run(
        arguments: [String],
        repositoryRoot: URL,
        temporaryDirectory: URL,
        startedAt: UInt64
    ) -> XcodeGraphToolResult {
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - startedAt) / 1_000_000_000
        let remaining = totalTimeoutSeconds - elapsed
        guard remaining > 0 else {
            return .unavailable
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = ["xcodebuild"] + arguments
        process.currentDirectoryURL = repositoryRoot
        process.standardInput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        var environment = ProcessInfo.processInfo.environment
        for key in [
            "CC", "CXX", "LD", "SDKROOT", "SWIFT_EXEC", "TOOLCHAINS",
            "XCODE_XCCONFIG_FILE", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH"
        ] {
            environment.removeValue(forKey: key)
        }
        environment["TMPDIR"] = temporaryDirectory.path
        process.environment = environment

        guard let result = try? BoundedProcessRunner.run(
            process,
            timeoutSeconds: min(invocationTimeoutSeconds, remaining),
            maximumOutputBytes: maximumOutputBytes
        ), result.exitedNormally,
           result.terminationStatus == 0,
           !result.timedOut,
           !result.outputLimitExceeded,
           result.outputDrainCompleted else {
            return .unavailable
        }
        return .success(result.output)
    }

    private static func prepareCachePaths(
        cacheRoot: URL,
        sandboxRoot: URL
    ) -> XcodeGraphCachePaths? {
        let paths = XcodeGraphCachePaths(
            derivedData: cacheRoot.appendingPathComponent("XcodeGraph/DerivedData", isDirectory: true),
            sourcePackages: cacheRoot.appendingPathComponent("XcodeGraph/SourcePackages", isDirectory: true),
            packageCache: cacheRoot.appendingPathComponent("XcodeGraph/PackageCache", isDirectory: true),
            temporary: cacheRoot.appendingPathComponent("XcodeGraph/Temporary", isDirectory: true)
        )
        guard ProfileValidator.resolvesWithinRepository(
            cacheRoot,
            root: sandboxRoot,
            allowingRoot: false
        ) else {
            return nil
        }

        let cacheDescriptor = Darwin.open(
            cacheRoot.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard cacheDescriptor >= 0 else {
            return nil
        }
        defer { Darwin.close(cacheDescriptor) }

        guard let graphDescriptor = openOrCreateDirectory(
            named: "XcodeGraph",
            parentDescriptor: cacheDescriptor
        ) else {
            return nil
        }
        defer { Darwin.close(graphDescriptor) }

        for name in ["DerivedData", "SourcePackages", "PackageCache", "Temporary"] {
            guard let descriptor = openOrCreateDirectory(
                named: name,
                parentDescriptor: graphDescriptor
            ) else {
                return nil
            }
            Darwin.close(descriptor)
        }

        guard paths.all.allSatisfy({
            ProfileValidator.resolvesWithinRepository(
                $0,
                root: sandboxRoot,
                allowingRoot: false
            )
        }) else {
            return nil
        }
        return paths
    }

    private static func openOrCreateDirectory(
        named name: String,
        parentDescriptor: Int32
    ) -> Int32? {
        let creationResult = name.withCString {
            Darwin.mkdirat(parentDescriptor, $0, S_IRWXU)
        }
        if creationResult != 0, errno != EEXIST {
            return nil
        }
        let descriptor = name.withCString {
            Darwin.openat(
                parentDescriptor,
                $0,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            )
        }
        return descriptor >= 0 ? descriptor : nil
    }

    private static func decodeInventory(
        _ data: Data,
        kind: ProjectReference.Kind
    ) -> Inventory? {
        guard (try? JSONDocumentConstraints.rejectDuplicateObjectKeys(in: data)) != nil,
              let document = try? JSONDecoder().decode(ListDocument.self, from: data) else {
            return nil
        }
        let container: ListContainer?
        switch kind {
        case .xcodeProject:
            container = document.project
        case .xcodeWorkspace:
            container = document.workspace
        }
        guard let container, !container.schemes.isEmpty else {
            return nil
        }
        return Inventory(
            configurations: Set(container.configurations),
            schemes: Set(container.schemes),
            targets: Set(container.targets)
        )
    }

    private static func decodeBuildSettings(_ data: Data) -> [BuildSettingsRecord]? {
        guard (try? JSONDocumentConstraints.rejectDuplicateObjectKeys(in: data)) != nil else {
            return nil
        }
        return try? JSONDecoder().decode([BuildSettingsRecord].self, from: data)
    }

    private static func projectDirectoryIsInsideRepository(
        _ path: String?,
        repositoryRoot: URL
    ) -> Bool {
        guard let path, path.hasPrefix("/") else {
            return false
        }
        return ProfileValidator.resolvesWithinRepository(
            URL(fileURLWithPath: path, isDirectory: true),
            root: repositoryRoot,
            allowingRoot: true
        )
    }

    private static func projectDirectoryIsInsideAllowedRoots(
        _ path: String?,
        repositoryRoot: URL,
        sourcePackagesRoot: URL
    ) -> Bool {
        guard let path, path.hasPrefix("/") else {
            return false
        }
        let candidate = URL(fileURLWithPath: path, isDirectory: true)
        return ProfileValidator.resolvesWithinRepository(
            candidate,
            root: repositoryRoot,
            allowingRoot: true
        ) || ProfileValidator.resolvesWithinRepository(
            candidate,
            root: sourcePackagesRoot,
            allowingRoot: true
        )
    }
}

typealias XcodeGraphToolRunner = (
    _ arguments: [String],
    _ repositoryRoot: URL,
    _ temporaryDirectory: URL,
    _ startedAt: UInt64
) -> XcodeGraphToolResult

enum XcodeGraphToolResult {
    case success(Data)
    case unavailable
}

struct XcodeGraphCachePaths {
    let derivedData: URL
    let sourcePackages: URL
    let packageCache: URL
    let temporary: URL

    var all: [URL] {
        [derivedData, sourcePackages, packageCache, temporary]
    }
}

private struct ListDocument: Decodable {
    let project: ListContainer?
    let workspace: ListContainer?
}

private struct ListContainer: Decodable {
    let configurations: [String]
    let schemes: [String]
    let targets: [String]

    private enum CodingKeys: String, CodingKey {
        case configurations
        case schemes
        case targets
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        configurations = try container.decodeIfPresent([String].self, forKey: .configurations) ?? []
        schemes = try container.decodeIfPresent([String].self, forKey: .schemes) ?? []
        targets = try container.decodeIfPresent([String].self, forKey: .targets) ?? []
    }
}

private struct Inventory {
    let configurations: Set<String>
    let schemes: Set<String>
    let targets: Set<String>
}

private struct BuildSettingsRecord: Decodable {
    let buildSettings: [String: String]
    let target: String
}
