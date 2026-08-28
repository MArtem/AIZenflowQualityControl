import Foundation
import Testing
@testable import QualityCore

@Suite("Xcode graph discovery")
struct XcodeGraphDiscoveryTests {
    @Test("Valid inventory and settings preserve source-membership BLOCKED")
    func validSelectionRemainsBlockedWithoutBuildEvidence() {
        let checks = discover(
            inventory: #"{"project":{"configurations":["Debug"],"schemes":["App"],"targets":["App"]}}"#,
            settings: #"[{"target":"App","buildSettings":{"CONFIGURATION":"Debug","PROJECT_DIR":"/repository"}}]"#
        )

        #expect(checks.map(\.id) == [
            "QC.DOCTOR.XCODE_GRAPH_SELECTION",
            "QC.DOCTOR.XCODE_SOURCE_MEMBERSHIP"
        ])
        #expect(checks.map(\.status) == [.pass, .blocked])
    }

    @Test("A missing declared scheme fails discovery")
    func missingSchemeFails() {
        let checks = discover(
            inventory: #"{"project":{"configurations":["Debug"],"schemes":["Other"],"targets":["App"]}}"#,
            settings: #"[]"#
        )

        #expect(checks.map(\.id) == ["QC.DOCTOR.XCODE_SCHEME_MISMATCH"])
        #expect(checks.first?.status == .fail)
    }

    @Test("Malformed Xcode inventory is blocked")
    func malformedInventoryBlocks() {
        let checks = discover(inventory: "not-json", settings: "[]")

        #expect(checks.map(\.id) == ["QC.DOCTOR.XCODE_INVENTORY"])
        #expect(checks.first?.status == .blocked)
    }

    private func discover(inventory: String, settings: String) -> [QualityCheck] {
        XcodeGraphDiscovery.checks(
            profile: profile,
            repositoryRoot: URL(fileURLWithPath: "/repository", isDirectory: true),
            paths: paths,
            execute: { arguments, _, _, _ in
                if arguments.contains("-list") {
                    return .success(Data(inventory.utf8))
                }
                return .success(Data(settings.utf8))
            },
            startedAt: DispatchTime.now().uptimeNanoseconds
        )
    }

    private var profile: ProjectProfile {
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
            sandbox: SandboxPaths(
                root: ".quality-control",
                cache: ".quality-control/cache"
            ),
            engine: EnginePin(
                version: "0.1.0",
                revision: "0123456789012345678901234567890123456789"
            ),
            xcode: XcodeConfiguration(
                sourceMembership: SourceMembership(authority: .xcodeBuildGraph),
                schemes: [
                    XcodeScheme(
                        name: "App",
                        targets: ["App"],
                        configurations: ["Debug"],
                        destinations: ["platform=macOS"],
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

    private var paths: XcodeGraphCachePaths {
        XcodeGraphCachePaths(
            derivedData: URL(fileURLWithPath: "/repository/.quality-control/cache/XcodeGraph/DerivedData", isDirectory: true),
            sourcePackages: URL(fileURLWithPath: "/repository/.quality-control/cache/XcodeGraph/SourcePackages", isDirectory: true),
            packageCache: URL(fileURLWithPath: "/repository/.quality-control/cache/XcodeGraph/PackageCache", isDirectory: true),
            temporary: URL(fileURLWithPath: "/repository/.quality-control/cache/XcodeGraph/Temporary", isDirectory: true)
        )
    }
}
