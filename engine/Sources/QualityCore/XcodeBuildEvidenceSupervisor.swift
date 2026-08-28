import Darwin
import Foundation

package struct XcodeBuildSelection: Equatable, Sendable {
    package let scheme: String
    package let configuration: String
    package let destination: String
}

package struct XcodeBuildSupervisionObservation: Equatable, Sendable {
    package let selection: XcodeBuildSelection
    package let resultBundlePath: String
    package let evidence: XcodeBuildEvidenceObservation
}

package enum XcodeBuildEvidenceSupervisionError: Error, Equatable {
    case invalidProfile
    case undeclaredSelection
    case repositoryBoundaryUnavailable
    case sandboxBoundaryUnavailable
    case layoutUnavailable
    case resultBundleAlreadyExists
    case buildInvocationUnavailable
    case resultBundleUnavailable
    case resultBundleLimitExceeded
    case resultBundleChanged
    case resultExtractionUnavailable
    case inconsistentResultReads
    case verification(XcodeBuildEvidenceVerificationError)
}

package struct XcodeBuildEvidenceLayout: Sendable {
    package let derivedData: URL
    package let sourcePackages: URL
    package let packageCache: URL
    package let temporary: URL
    package let resultBundle: URL
}

package struct XcodeResultBundleIdentity: Equatable, Sendable {
    package let device: UInt64
    package let inode: UInt64
    package let owner: UInt32
}

package enum XcodeStructuredResultKind: Sendable {
    case buildResults
    case buildLog
}

package typealias XcodeBuildInvocationRunner = (
    _ arguments: [String],
    _ repositoryRoot: URL,
    _ temporaryDirectory: URL
) throws -> BoundedProcessResult

package typealias XcodeStructuredResultReader = (
    _ kind: XcodeStructuredResultKind,
    _ resultBundle: URL,
    _ repositoryRoot: URL,
    _ temporaryDirectory: URL
) throws -> Data

package typealias XcodeResultBundleObserver = (
    _ resultBundle: URL
) -> XcodeResultBundleIdentity?

package typealias XcodeResultBundleValidator = (
    _ resultBundle: URL
) -> Bool

/// Fixed process environment for Xcode evidence commands.
///
/// Build-setting and toolchain overrides are intentionally not inherited from the caller because
/// they are not declared by the profile or bound into the command identity. `TMPDIR` is the only
/// machine-local value and is supplied from the already validated sandbox layout.
package enum XcodeBuildProcessEnvironment {
    package static func make(temporaryDirectory: URL? = nil) -> [String: String] {
        var environment = [
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "LANG": "en_US.UTF-8",
            "LC_ALL": "en_US.UTF-8",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"
        ]
        if let temporaryDirectory {
            environment["TMPDIR"] = temporaryDirectory.path
        }
        return environment
    }
}

/// Supervises one declared Xcode build matrix entry and binds stable structured result reads.
///
/// The production boundary prevents path replacement and detects mutation across two complete read
/// cycles. It does not claim isolation from an independently malicious process running as the same
/// operating-system user; stronger adversarial isolation requires an ephemeral runner or VM.
package enum XcodeBuildEvidenceSupervisor {
    private static let buildTimeoutSeconds: TimeInterval = 15 * 60
    private static let buildOutputBytes = 8 * 1_024 * 1_024
    private static let resultReadTimeoutSeconds: TimeInterval = 60
    private static let maximumResultBundleEntries = 200_000
    private static let maximumResultBundleBytes: Int64 = 8 * 1_024 * 1_024 * 1_024

    package static func supervise(
        profile: ProjectProfile,
        repositoryRoot: URL,
        selection: XcodeBuildSelection
    ) throws -> XcodeBuildSupervisionObservation {
        guard profileIsValidForBuild(profile) else {
            throw XcodeBuildEvidenceSupervisionError.invalidProfile
        }
        guard selectionIsDeclared(selection, in: profile) else {
            throw XcodeBuildEvidenceSupervisionError.undeclaredSelection
        }
        guard validatedProjectURL(profile: profile, repositoryRoot: repositoryRoot) != nil else {
            throw XcodeBuildEvidenceSupervisionError.repositoryBoundaryUnavailable
        }
        guard let layout = prepareLayout(profile: profile, repositoryRoot: repositoryRoot) else {
            throw XcodeBuildEvidenceSupervisionError.layoutUnavailable
        }
        return try supervise(
            profile: profile,
            repositoryRoot: repositoryRoot,
            selection: selection,
            layout: layout,
            runBuild: runBuild,
            readResult: readResult,
            observeBundle: observeBundle,
            validateBundle: resultBundleIsWithinLimits
        )
    }

    package static func supervise(
        profile: ProjectProfile,
        repositoryRoot: URL,
        selection: XcodeBuildSelection,
        layout: XcodeBuildEvidenceLayout,
        runBuild: XcodeBuildInvocationRunner,
        readResult: XcodeStructuredResultReader,
        observeBundle: XcodeResultBundleObserver,
        validateBundle: XcodeResultBundleValidator
    ) throws -> XcodeBuildSupervisionObservation {
        guard profileIsValidForBuild(profile),
              let xcode = profile.xcode else {
            throw XcodeBuildEvidenceSupervisionError.invalidProfile
        }
        guard !xcode.schemes.isEmpty, selectionIsDeclared(selection, in: profile) else {
            throw XcodeBuildEvidenceSupervisionError.undeclaredSelection
        }

        let canonicalRepositoryRoot = repositoryRoot.resolvingSymlinksInPath().standardizedFileURL
        guard let projectURL = validatedProjectURL(
            profile: profile,
            repositoryRoot: repositoryRoot
        ) else {
            throw XcodeBuildEvidenceSupervisionError.repositoryBoundaryUnavailable
        }
        guard layoutPathsRemainInSandbox(
            layout,
            profile: profile,
            repositoryRoot: repositoryRoot
        ) else {
            throw XcodeBuildEvidenceSupervisionError.sandboxBoundaryUnavailable
        }
        guard observeBundle(layout.resultBundle) == nil else {
            throw XcodeBuildEvidenceSupervisionError.resultBundleAlreadyExists
        }

        let processResult: BoundedProcessResult
        do {
            processResult = try runBuild(
                buildArguments(
                    profile: profile,
                    projectURL: projectURL,
                    selection: selection,
                    layout: layout
                ),
                canonicalRepositoryRoot,
                layout.temporary
            )
        } catch {
            throw XcodeBuildEvidenceSupervisionError.buildInvocationUnavailable
        }

        guard processResult.exitedNormally,
              processResult.terminationStatus == 0,
              !processResult.timedOut,
              !processResult.outputLimitExceeded,
              processResult.outputDrainCompleted else {
            do {
                _ = try XcodeBuildEvidenceVerifier.verify(
                    processResult: processResult,
                    buildResultsData: Data(),
                    buildLogData: Data(),
                    repositoryRoot: canonicalRepositoryRoot,
                    sourcePaths: profile.sourcePaths
                )
                throw XcodeBuildEvidenceSupervisionError.buildInvocationUnavailable
            } catch let error as XcodeBuildEvidenceVerificationError {
                throw XcodeBuildEvidenceSupervisionError.verification(error)
            }
        }

        guard let bundleIdentity = observeBundle(layout.resultBundle) else {
            throw XcodeBuildEvidenceSupervisionError.resultBundleUnavailable
        }
        guard validateBundle(layout.resultBundle) else {
            throw XcodeBuildEvidenceSupervisionError.resultBundleLimitExceeded
        }

        let firstBuildResults = try stableRead(
            .buildResults,
            expectedIdentity: bundleIdentity,
            layout: layout,
            repositoryRoot: canonicalRepositoryRoot,
            readResult: readResult,
            observeBundle: observeBundle
        )
        let firstBuildLog = try stableRead(
            .buildLog,
            expectedIdentity: bundleIdentity,
            layout: layout,
            repositoryRoot: canonicalRepositoryRoot,
            readResult: readResult,
            observeBundle: observeBundle
        )
        let secondBuildResults = try stableRead(
            .buildResults,
            expectedIdentity: bundleIdentity,
            layout: layout,
            repositoryRoot: canonicalRepositoryRoot,
            readResult: readResult,
            observeBundle: observeBundle
        )
        let secondBuildLog = try stableRead(
            .buildLog,
            expectedIdentity: bundleIdentity,
            layout: layout,
            repositoryRoot: canonicalRepositoryRoot,
            readResult: readResult,
            observeBundle: observeBundle
        )
        guard firstBuildResults == secondBuildResults,
              firstBuildLog == secondBuildLog else {
            throw XcodeBuildEvidenceSupervisionError.inconsistentResultReads
        }

        let evidence: XcodeBuildEvidenceObservation
        do {
            evidence = try XcodeBuildEvidenceVerifier.verify(
                processResult: processResult,
                buildResultsData: firstBuildResults,
                buildLogData: firstBuildLog,
                repositoryRoot: canonicalRepositoryRoot,
                sourcePaths: profile.sourcePaths
            )
        } catch let error as XcodeBuildEvidenceVerificationError {
            throw XcodeBuildEvidenceSupervisionError.verification(error)
        }
        guard observeBundle(layout.resultBundle) == bundleIdentity else {
            throw XcodeBuildEvidenceSupervisionError.resultBundleChanged
        }
        guard validateBundle(layout.resultBundle) else {
            throw XcodeBuildEvidenceSupervisionError.resultBundleLimitExceeded
        }

        return XcodeBuildSupervisionObservation(
            selection: selection,
            resultBundlePath: layout.resultBundle.path,
            evidence: evidence
        )
    }

    private static func stableRead(
        _ kind: XcodeStructuredResultKind,
        expectedIdentity: XcodeResultBundleIdentity,
        layout: XcodeBuildEvidenceLayout,
        repositoryRoot: URL,
        readResult: XcodeStructuredResultReader,
        observeBundle: XcodeResultBundleObserver
    ) throws -> Data {
        guard observeBundle(layout.resultBundle) == expectedIdentity else {
            throw XcodeBuildEvidenceSupervisionError.resultBundleChanged
        }
        let data: Data
        do {
            data = try readResult(
                kind,
                layout.resultBundle,
                repositoryRoot,
                layout.temporary
            )
        } catch {
            throw XcodeBuildEvidenceSupervisionError.resultExtractionUnavailable
        }
        guard observeBundle(layout.resultBundle) == expectedIdentity else {
            throw XcodeBuildEvidenceSupervisionError.resultBundleChanged
        }
        return data
    }

    private static func buildArguments(
        profile: ProjectProfile,
        projectURL: URL,
        selection: XcodeBuildSelection,
        layout: XcodeBuildEvidenceLayout
    ) -> [String] {
        let containerArguments: [String]
        switch profile.project.kind {
        case .xcodeProject:
            containerArguments = ["-project", projectURL.path]
        case .xcodeWorkspace:
            containerArguments = ["-workspace", projectURL.path]
        }
        return containerArguments + [
            "-scheme", selection.scheme,
            "-configuration", selection.configuration,
            "-destination", selection.destination,
            "-disableAutomaticPackageResolution",
            "-onlyUsePackageVersionsFromResolvedFile",
            "-skipPackageUpdates",
            "-clonedSourcePackagesDirPath", layout.sourcePackages.path,
            "-packageCachePath", layout.packageCache.path,
            "-derivedDataPath", layout.derivedData.path,
            "-resultBundlePath", layout.resultBundle.path,
            "-quiet",
            "build"
        ]
    }

    private static func runBuild(
        arguments: [String],
        repositoryRoot: URL,
        temporaryDirectory: URL
    ) throws -> BoundedProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = ["xcodebuild"] + arguments
        process.currentDirectoryURL = repositoryRoot
        process.standardInput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.environment = sanitizedEnvironment(temporaryDirectory: temporaryDirectory)
        return try BoundedProcessRunner.run(
            process,
            timeoutSeconds: buildTimeoutSeconds,
            maximumOutputBytes: buildOutputBytes
        )
    }

    private static func readResult(
        kind: XcodeStructuredResultKind,
        resultBundle: URL,
        repositoryRoot: URL,
        temporaryDirectory: URL
    ) throws -> Data {
        let commandArguments: [String]
        let maximumOutputBytes: Int
        switch kind {
        case .buildResults:
            commandArguments = [
                "xcresulttool", "get", "build-results",
                "--path", resultBundle.path,
                "--schema-version", XcodeBuildEvidenceObservation.buildResultsSchemaVersion,
                "--compact"
            ]
            maximumOutputBytes = XcodeBuildEvidenceVerifier.maximumBuildResultsBytes
        case .buildLog:
            commandArguments = [
                "xcresulttool", "get", "log",
                "--type", "build",
                "--path", resultBundle.path,
                "--schema-version", XcodeBuildLogMembershipObservation.logSchemaVersion,
                "--compact"
            ]
            maximumOutputBytes = XcodeBuildLogMembershipExtractor.maximumDocumentBytes
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = commandArguments
        process.currentDirectoryURL = repositoryRoot
        process.standardInput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.environment = sanitizedEnvironment(temporaryDirectory: temporaryDirectory)
        let result = try BoundedProcessRunner.run(
            process,
            timeoutSeconds: resultReadTimeoutSeconds,
            maximumOutputBytes: maximumOutputBytes
        )
        guard result.exitedNormally,
              result.terminationStatus == 0,
              !result.timedOut,
              !result.outputLimitExceeded,
              result.outputDrainCompleted else {
            throw XcodeBuildEvidenceSupervisionError.resultExtractionUnavailable
        }
        return result.output
    }

    private static func sanitizedEnvironment(temporaryDirectory: URL) -> [String: String] {
        XcodeBuildProcessEnvironment.make(temporaryDirectory: temporaryDirectory)
    }

    private static func prepareLayout(
        profile: ProjectProfile,
        repositoryRoot: URL
    ) -> XcodeBuildEvidenceLayout? {
        guard let sandboxPaths = ProfileValidator.resolveSandboxPaths(
            for: profile,
            under: repositoryRoot
        ) else {
            return nil
        }
        let sandboxRoot = sandboxPaths.root
        let cacheRoot = sandboxPaths.cache
        guard canonicalDirectory(sandboxRoot) != nil,
              canonicalDirectory(cacheRoot) != nil,
              sandboxRootRemainsInRepository(
                  sandboxRoot,
                  profile: profile,
                  repositoryRoot: repositoryRoot
              ),
              ProfileValidator.resolvesWithinRepository(
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

        guard let evidenceDescriptor = openOrCreateDirectory(
            named: "XcodeBuildEvidence",
            parentDescriptor: cacheDescriptor
        ) else {
            return nil
        }
        defer { Darwin.close(evidenceDescriptor) }

        var sourcePackagesDescriptor: Int32?
        var packageCacheDescriptor: Int32?
        defer {
            if let sourcePackagesDescriptor { Darwin.close(sourcePackagesDescriptor) }
            if let packageCacheDescriptor { Darwin.close(packageCacheDescriptor) }
        }
        sourcePackagesDescriptor = openOrCreateDirectory(
            named: "SourcePackages",
            parentDescriptor: evidenceDescriptor
        )
        packageCacheDescriptor = openOrCreateDirectory(
            named: "PackageCache",
            parentDescriptor: evidenceDescriptor
        )
        guard sourcePackagesDescriptor != nil, packageCacheDescriptor != nil,
              let invocation = createUniqueDirectory(parentDescriptor: evidenceDescriptor) else {
            return nil
        }
        defer { Darwin.close(invocation.descriptor) }

        guard let derivedDataDescriptor = openOrCreateDirectory(
                  named: "DerivedData",
                  parentDescriptor: invocation.descriptor
              ),
              let temporaryDescriptor = openOrCreateDirectory(
                  named: "Temporary",
                  parentDescriptor: invocation.descriptor
              ) else {
            return nil
        }
        Darwin.close(derivedDataDescriptor)
        Darwin.close(temporaryDescriptor)

        let evidenceRoot = cacheRoot.appendingPathComponent(
            "XcodeBuildEvidence",
            isDirectory: true
        )
        let invocationRoot = evidenceRoot.appendingPathComponent(
            invocation.name,
            isDirectory: true
        )
        let layout = XcodeBuildEvidenceLayout(
            derivedData: invocationRoot.appendingPathComponent("DerivedData", isDirectory: true),
            sourcePackages: evidenceRoot.appendingPathComponent("SourcePackages", isDirectory: true),
            packageCache: evidenceRoot.appendingPathComponent("PackageCache", isDirectory: true),
            temporary: invocationRoot.appendingPathComponent("Temporary", isDirectory: true),
            resultBundle: invocationRoot.appendingPathComponent("Build.xcresult", isDirectory: true)
        )
        return layoutPathsRemainInSandbox(
            layout,
            profile: profile,
            repositoryRoot: repositoryRoot
        ) ? layout : nil
    }

    private static func layoutPathsRemainInSandbox(
        _ layout: XcodeBuildEvidenceLayout,
        profile: ProjectProfile,
        repositoryRoot: URL
    ) -> Bool {
        guard let sandboxRoot = ProfileValidator.resolveSandboxPaths(
            for: profile,
            under: repositoryRoot
        )?.root,
        canonicalDirectory(sandboxRoot) != nil,
        sandboxRootRemainsInRepository(
            sandboxRoot,
            profile: profile,
            repositoryRoot: repositoryRoot
        ) else {
            return false
        }
        return [
            layout.derivedData,
            layout.sourcePackages,
            layout.packageCache,
            layout.temporary,
            layout.resultBundle
        ].allSatisfy {
            ProfileValidator.resolvesWithinRepository(
                $0,
                root: sandboxRoot,
                allowingRoot: false
            )
        }
    }

    private static func sandboxRootRemainsInRepository(
        _ sandboxRoot: URL,
        profile: ProjectProfile,
        repositoryRoot: URL
    ) -> Bool {
        profile.schemaVersion != 2 || ProfileValidator.resolvesWithinRepository(
            sandboxRoot,
            root: repositoryRoot,
            allowingRoot: false
        )
    }

    private static func profileIsValidForBuild(_ profile: ProjectProfile) -> Bool {
        let issues = ProfileValidator.validate(profile).filter {
            $0.code != "QC.PROFILE.XCODE_GRAPH_RESOLUTION_REQUIRED"
        }
        return profile.schemaVersion == 2 && profile.xcode != nil && issues.isEmpty
    }

    private static func selectionIsDeclared(
        _ selection: XcodeBuildSelection,
        in profile: ProjectProfile
    ) -> Bool {
        profile.xcode?.schemes.contains(where: { scheme in
            scheme.name == selection.scheme
                && scheme.configurations.contains(selection.configuration)
                && scheme.destinations.contains(selection.destination)
        }) == true
    }

    private static func validatedProjectURL(
        profile: ProjectProfile,
        repositoryRoot: URL
    ) -> URL? {
        let canonicalRepositoryRoot = repositoryRoot
            .resolvingSymlinksInPath()
            .standardizedFileURL
        guard canonicalDirectory(repositoryRoot) == canonicalRepositoryRoot,
              let projectURL = ProfileValidator.resolve(
                  relativePath: profile.project.path,
                  under: canonicalRepositoryRoot
              ),
              canonicalDirectory(projectURL) != nil,
              ProfileValidator.resolvesWithinRepository(
                  projectURL,
                  root: canonicalRepositoryRoot,
                  allowingRoot: false
              ) else {
            return nil
        }
        return projectURL
    }

    private static func observeBundle(_ resultBundle: URL) -> XcodeResultBundleIdentity? {
        var status = stat()
        guard lstat(resultBundle.path, &status) == 0,
              status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == geteuid() else {
            return nil
        }
        return XcodeResultBundleIdentity(
            device: UInt64(status.st_dev),
            inode: UInt64(status.st_ino),
            owner: UInt32(status.st_uid)
        )
    }

    private static func resultBundleIsWithinLimits(_ resultBundle: URL) -> Bool {
        let resourceKeys: Set<URLResourceKey> = [
            .fileSizeKey,
            .isDirectoryKey,
            .isRegularFileKey,
            .isSymbolicLinkKey
        ]
        var enumerationFailed = false
        guard let enumerator = FileManager.default.enumerator(
            at: resultBundle,
            includingPropertiesForKeys: Array(resourceKeys),
            options: [],
            errorHandler: { _, _ in
                enumerationFailed = true
                return false
            }
        ) else {
            return false
        }

        var entryCount = 0
        var totalBytes: Int64 = 0
        for case let item as URL in enumerator {
            entryCount += 1
            guard entryCount <= maximumResultBundleEntries,
                  let values = try? item.resourceValues(forKeys: resourceKeys),
                  values.isSymbolicLink != true else {
                return false
            }
            if values.isRegularFile == true {
                guard let fileSize = values.fileSize, fileSize >= 0,
                      totalBytes <= maximumResultBundleBytes - Int64(fileSize) else {
                    return false
                }
                totalBytes += Int64(fileSize)
            } else if values.isDirectory != true {
                return false
            }
        }
        return !enumerationFailed
    }

    private static func canonicalDirectory(_ url: URL) -> URL? {
        let descriptor = Darwin.open(
            url.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            return nil
        }
        Darwin.close(descriptor)
        return url.resolvingSymlinksInPath().standardizedFileURL
    }

    private static func openOrCreateDirectory(
        named name: String,
        parentDescriptor: Int32
    ) -> Int32? {
        let creation = name.withCString {
            Darwin.mkdirat(parentDescriptor, $0, S_IRWXU)
        }
        guard creation == 0 || errno == EEXIST else {
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

    private static func createUniqueDirectory(
        parentDescriptor: Int32
    ) -> (name: String, descriptor: Int32)? {
        for _ in 0..<8 {
            let name = "Invocation-" + UUID().uuidString
            let creation = name.withCString {
                Darwin.mkdirat(parentDescriptor, $0, S_IRWXU)
            }
            if creation == 0 {
                let descriptor = name.withCString {
                    Darwin.openat(
                        parentDescriptor,
                        $0,
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
                    )
                }
                if descriptor >= 0 {
                    return (name, descriptor)
                }
                return nil
            }
            guard errno == EEXIST else {
                return nil
            }
        }
        return nil
    }
}
