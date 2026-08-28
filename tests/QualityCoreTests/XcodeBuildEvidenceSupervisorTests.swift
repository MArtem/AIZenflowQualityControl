import Foundation
import Testing
@testable import QualityCore

@Suite("Xcode build evidence supervision")
struct XcodeBuildEvidenceSupervisorTests {
    @Test("Xcode evidence subprocesses do not inherit unbound build overrides")
    func buildEnvironmentIsFixedAndMinimal() {
        let temporaryDirectory = URL(fileURLWithPath: "/sandbox/temporary", isDirectory: true)
        let environment = XcodeBuildProcessEnvironment.make(
            temporaryDirectory: temporaryDirectory
        )

        #expect(environment["TMPDIR"] == temporaryDirectory.path)
        #expect(environment["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin")
        #expect(environment["OTHER_SWIFT_FLAGS"] == nil)
        #expect(environment["XCODE_XCCONFIG_FILE"] == nil)
        #expect(environment["DEVELOPER_DIR"] == nil)
        #expect(Set(environment.keys) == Set([
            "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_SYSTEM",
            "GIT_NO_REPLACE_OBJECTS", "LANG", "LC_ALL", "PATH", "TMPDIR"
        ]))
    }

    @Test("Declared selection binds one stable build invocation and two result read cycles")
    func supervisesStableDeclaredBuild() throws {
        let fixture = try makeFixture()
        defer { remove(fixture) }
        var bundleExists = false
        var arguments: [String] = []
        var reads: [String] = []

        let observation = try XcodeBuildEvidenceSupervisor.supervise(
            profile: fixture.profile,
            repositoryRoot: fixture.repositoryRoot,
            selection: fixture.selection,
            layout: fixture.layout,
            runBuild: { invocation, _, _ in
                arguments = invocation
                bundleExists = true
                return successfulProcess
            },
            readResult: { kind, _, _, _ in
                reads.append(kind == .buildResults ? "build-results" : "build-log")
                switch kind {
                case .buildResults: return try buildResults()
                case .buildLog: return try buildLog(repositoryRoot: fixture.repositoryRoot)
                }
            },
            observeBundle: { _ in bundleExists ? fixture.identity : nil },
            validateBundle: { _ in true }
        )

        #expect(observation.selection == fixture.selection)
        #expect(observation.evidence.compiledSourcePaths == ["Sources/App.swift"])
        #expect(reads == ["build-results", "build-log", "build-results", "build-log"])
        #expect(arguments.contains("-disableAutomaticPackageResolution"))
        #expect(arguments.contains("-onlyUsePackageVersionsFromResolvedFile"))
        #expect(arguments.contains("-skipPackageUpdates"))
        #expect(arguments.contains("-resultBundlePath"))
        #expect(arguments.last == "build")
    }

    @Test("An undeclared selection is rejected before starting a build")
    func rejectsUndeclaredSelectionBeforeBuild() throws {
        let fixture = try makeFixture()
        defer { remove(fixture) }

        expectError(.undeclaredSelection) {
            try XcodeBuildEvidenceSupervisor.supervise(
                profile: fixture.profile,
                repositoryRoot: fixture.repositoryRoot,
                selection: XcodeBuildSelection(
                    scheme: "Other",
                    configuration: fixture.selection.configuration,
                    destination: fixture.selection.destination
                ),
                layout: fixture.layout,
                runBuild: { _, _, _ in
                    Issue.record("Undeclared selection must not start xcodebuild.")
                    return successfulProcess
                },
                readResult: { _, _, _, _ in Data() },
                observeBundle: { _ in nil },
                validateBundle: { _ in true }
            )
        }
    }

    @Test("An absolute schemaVersion 2 sandbox is rejected before starting a build")
    func rejectsAbsolutePortableSandboxBeforeBuild() throws {
        let fixture = try makeFixture(
            profileSandboxRoot: "/sandbox",
            profileSandboxCache: "/sandbox/cache"
        )
        defer { remove(fixture) }

        expectError(.invalidProfile) {
            try XcodeBuildEvidenceSupervisor.supervise(
                profile: fixture.profile,
                repositoryRoot: fixture.repositoryRoot,
                selection: fixture.selection,
                layout: fixture.layout,
                runBuild: { _, _, _ in
                    Issue.record("An invalid portable sandbox must not start xcodebuild.")
                    return successfulProcess
                },
                readResult: { _, _, _, _ in Data() },
                observeBundle: { _ in nil },
                validateBundle: { _ in true }
            )
        }
    }

    @Test("A schemaVersion 2 sandbox symlink cannot escape the repository")
    func rejectsPortableSandboxSymlinkEscapeBeforeBuild() throws {
        let fixture = try makeFixture()
        defer { remove(fixture) }
        try fixture.temporaryProfile.createDirectory(at: "outside/cache/evidence")
        try fixture.temporaryProfile.createSymbolicLink(
            at: "repository/escaped",
            destination: "../outside"
        )
        let escapedRoot = fixture.temporaryProfile.directory
            .appendingPathComponent("outside", isDirectory: true)
        let escapedEvidence = escapedRoot
            .appendingPathComponent("cache/evidence", isDirectory: true)

        expectError(.sandboxBoundaryUnavailable) {
            try XcodeBuildEvidenceSupervisor.supervise(
                profile: profile(
                    sandboxRoot: "escaped",
                    sandboxCache: "escaped/cache",
                    selection: fixture.selection
                ),
                repositoryRoot: fixture.repositoryRoot,
                selection: fixture.selection,
                layout: XcodeBuildEvidenceLayout(
                    derivedData: escapedEvidence.appendingPathComponent("DerivedData", isDirectory: true),
                    sourcePackages: escapedEvidence.appendingPathComponent("SourcePackages", isDirectory: true),
                    packageCache: escapedEvidence.appendingPathComponent("PackageCache", isDirectory: true),
                    temporary: escapedEvidence.appendingPathComponent("Temporary", isDirectory: true),
                    resultBundle: escapedEvidence.appendingPathComponent("Build.xcresult", isDirectory: true)
                ),
                runBuild: { _, _, _ in
                    Issue.record("An escaped portable sandbox must not start xcodebuild.")
                    return successfulProcess
                },
                readResult: { _, _, _, _ in Data() },
                observeBundle: { _ in nil },
                validateBundle: { _ in true }
            )
        }
    }

    @Test(
        "Unsafe schemaVersion 2 sandbox forms fail profile validation",
        arguments: [
            (".quality-control//runtime", ".quality-control//runtime/cache", "QC.PROFILE.NON_NORMALIZED_SANDBOX_PATH"),
            (".quality-control/runtime", ".quality-control/runtime/../cache", "QC.PROFILE.PATH_TRAVERSAL"),
            (".quality-control/runtime", ".quality-control/cache", "QC.PROFILE.CACHE_OUTSIDE_SANDBOX")
        ]
    )
    func rejectsUnsafePortableSandboxForms(
        root: String,
        cache: String,
        expectedCode: String
    ) {
        let selection = XcodeBuildSelection(
            scheme: "App",
            configuration: "Debug",
            destination: "platform=macOS"
        )
        let issues = ProfileValidator.validate(
            profile(sandboxRoot: root, sandboxCache: cache, selection: selection)
        )

        #expect(issues.contains { $0.code == expectedCode })
    }

    @Test("A failed xcodebuild process is propagated through the verifier")
    func propagatesFailedBuildProcess() throws {
        let fixture = try makeFixture()
        defer { remove(fixture) }

        expectError(.verification(.buildProcessFailed(1))) {
            try XcodeBuildEvidenceSupervisor.supervise(
                profile: fixture.profile,
                repositoryRoot: fixture.repositoryRoot,
                selection: fixture.selection,
                layout: fixture.layout,
                runBuild: { _, _, _ in
                    BoundedProcessResult(
                        output: Data(),
                        terminationStatus: 1,
                        exitedNormally: true,
                        timedOut: false,
                        outputLimitExceeded: false,
                        outputDrainCompleted: true
                    )
                },
                readResult: { _, _, _, _ in
                    Issue.record("Failed xcodebuild must not read a result bundle.")
                    return Data()
                },
                observeBundle: { _ in nil },
                validateBundle: { _ in true }
            )
        }
    }

    @Test("Identity replacement during a structured read is rejected")
    func rejectsBundleIdentityReplacement() throws {
        let fixture = try makeFixture()
        defer { remove(fixture) }
        var bundleExists = false
        var observationsAfterBuild = 0
        let replacedIdentity = XcodeResultBundleIdentity(device: 9, inode: 9, owner: 9)

        expectError(.resultBundleChanged) {
            try XcodeBuildEvidenceSupervisor.supervise(
                profile: fixture.profile,
                repositoryRoot: fixture.repositoryRoot,
                selection: fixture.selection,
                layout: fixture.layout,
                runBuild: { _, _, _ in
                    bundleExists = true
                    return successfulProcess
                },
                readResult: { kind, _, _, _ in
                    switch kind {
                    case .buildResults: return try buildResults()
                    case .buildLog: return try buildLog(repositoryRoot: fixture.repositoryRoot)
                    }
                },
                observeBundle: { _ in
                    guard bundleExists else { return nil }
                    observationsAfterBuild += 1
                    return observationsAfterBuild >= 3 ? replacedIdentity : fixture.identity
                },
                validateBundle: { _ in true }
            )
        }
    }

    @Test("Changed bytes across repeated reads are rejected")
    func rejectsChangedStructuredResultReads() throws {
        let fixture = try makeFixture()
        defer { remove(fixture) }
        var bundleExists = false
        var buildResultsReads = 0

        expectError(.inconsistentResultReads) {
            try XcodeBuildEvidenceSupervisor.supervise(
                profile: fixture.profile,
                repositoryRoot: fixture.repositoryRoot,
                selection: fixture.selection,
                layout: fixture.layout,
                runBuild: { _, _, _ in
                    bundleExists = true
                    return successfulProcess
                },
                readResult: { kind, _, _, _ in
                    switch kind {
                    case .buildResults:
                        buildResultsReads += 1
                        return try buildResults(
                            actionTitle: buildResultsReads == 1 ? "Build" : "Changed Build"
                        )
                    case .buildLog:
                        return try buildLog(repositoryRoot: fixture.repositoryRoot)
                    }
                },
                observeBundle: { _ in bundleExists ? fixture.identity : nil },
                validateBundle: { _ in true }
            )
        }
    }

    private struct Fixture {
        let temporaryProfile: TemporaryProfile
        let repositoryRoot: URL
        let profile: ProjectProfile
        let layout: XcodeBuildEvidenceLayout
        let selection: XcodeBuildSelection
        let identity = XcodeResultBundleIdentity(device: 1, inode: 2, owner: 3)
    }

    private func makeFixture(
        profileSandboxRoot: String = "sandbox",
        profileSandboxCache: String = "sandbox/cache"
    ) throws -> Fixture {
        let temporaryProfile = try TemporaryProfile(data: Data("{}".utf8))
        try temporaryProfile.createDirectory(at: "repository/App.xcodeproj")
        try temporaryProfile.createDirectory(at: "repository/Sources")
        try temporaryProfile.createDirectory(at: "repository/sandbox/cache")

        let repositoryRoot = temporaryProfile.directory
            .appendingPathComponent("repository", isDirectory: true)
        let sandboxRoot = repositoryRoot.appendingPathComponent("sandbox", isDirectory: true)
        let cacheRoot = sandboxRoot.appendingPathComponent("cache", isDirectory: true)
        let evidenceRoot = cacheRoot.appendingPathComponent("evidence", isDirectory: true)
        let selection = XcodeBuildSelection(
            scheme: "App",
            configuration: "Debug",
            destination: "platform=macOS"
        )
        return Fixture(
            temporaryProfile: temporaryProfile,
            repositoryRoot: repositoryRoot,
            profile: profile(
                sandboxRoot: profileSandboxRoot,
                sandboxCache: profileSandboxCache,
                selection: selection
            ),
            layout: XcodeBuildEvidenceLayout(
                derivedData: evidenceRoot.appendingPathComponent("DerivedData", isDirectory: true),
                sourcePackages: evidenceRoot.appendingPathComponent("SourcePackages", isDirectory: true),
                packageCache: evidenceRoot.appendingPathComponent("PackageCache", isDirectory: true),
                temporary: evidenceRoot.appendingPathComponent("Temporary", isDirectory: true),
                resultBundle: evidenceRoot.appendingPathComponent("Build.xcresult", isDirectory: true)
            ),
            selection: selection
        )
    }

    private func profile(
        sandboxRoot: String,
        sandboxCache: String,
        selection: XcodeBuildSelection
    ) -> ProjectProfile {
        ProjectProfile(
            schemaVersion: 2,
            project: ProjectReference(kind: .xcodeProject, path: "App.xcodeproj"),
            scheme: nil,
            sourcePaths: ["Sources"],
            mode: .controlled,
            permissions: PermissionPolicy(
                testCreation: .allow,
                testModification: .allow,
                localTestExecution: .allow,
                githubExecution: .manual,
                uiTests: .deny,
                simulatorOrDevice: .deny,
                performanceOrInstruments: .deny
            ),
            sandbox: SandboxPaths(root: sandboxRoot, cache: sandboxCache),
            engine: EnginePin(
                version: "0.1.0",
                revision: "0123456789012345678901234567890123456789"
            ),
            xcode: XcodeConfiguration(
                sourceMembership: SourceMembership(authority: .xcodeBuildGraph),
                schemes: [
                    XcodeScheme(
                        name: selection.scheme,
                        targets: ["App"],
                        configurations: [selection.configuration],
                        destinations: [selection.destination],
                        testPlans: []
                    )
                ]
            ),
            applicability: CapabilityID.allCases.map {
                CapabilityApplicability(
                    capability: $0,
                    status: .applicable,
                    reason: "Covered by the quality profile.",
                    owner: "Quality control",
                    revisitCondition: "Profile version changes."
                )
            }
        )
    }

    private var successfulProcess: BoundedProcessResult {
        BoundedProcessResult(
            output: Data(),
            terminationStatus: 0,
            exitedNormally: true,
            timedOut: false,
            outputLimitExceeded: false,
            outputDrainCompleted: true
        )
    }

    private func buildResults(actionTitle: String = "Build") throws -> Data {
        try JSONSerialization.data(
            withJSONObject: [
                "actionTitle": actionTitle,
                "analyzerWarnings": [],
                "destination": [
                    "architecture": "arm64",
                    "deviceId": "device-id",
                    "deviceName": "Mac",
                    "modelName": "Mac",
                    "osVersion": "15.0"
                ],
                "endTime": 2.0,
                "errors": [],
                "startTime": 1.0,
                "status": "succeeded",
                "warnings": []
            ],
            options: [.sortedKeys]
        )
    }

    private func buildLog(repositoryRoot: URL) throws -> Data {
        try JSONSerialization.data(
            withJSONObject: [
                "commandInvocationDetails": [
                    "commandDetails": "/usr/bin/swiftc -frontend -c \(repositoryRoot.path)/Sources/App.swift"
                ],
                "messages": [],
                "subsections": []
            ],
            options: [.sortedKeys]
        )
    }

    private func remove(_ fixture: Fixture) {
        do {
            try fixture.temporaryProfile.remove()
        } catch {
            Issue.record("Fixture cleanup failed: \(error)")
        }
    }

    private func expectError(
        _ expected: XcodeBuildEvidenceSupervisionError,
        operation: () throws -> XcodeBuildSupervisionObservation
    ) {
        do {
            _ = try operation()
            Issue.record("Expected XcodeBuildEvidenceSupervisionError.\(expected)")
        } catch let error as XcodeBuildEvidenceSupervisionError {
            #expect(error == expected)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }
}
