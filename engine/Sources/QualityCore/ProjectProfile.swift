import Foundation

public struct ProjectProfile: Codable, Sendable {
    public let schemaVersion: Int
    public let project: ProjectReference
    public let scheme: String
    public let sourcePaths: [String]
    public let mode: ProjectMode
    public let permissions: PermissionPolicy
    public let sandbox: SandboxPaths
}

public struct ProjectReference: Codable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case xcodeProject = "xcodeproj"
        case xcodeWorkspace = "xcworkspace"
    }

    public let kind: Kind
    public let path: String
}

public enum ProjectMode: String, Codable, Equatable, Sendable {
    case prototype
    case controlled
    case production
}

public enum PermissionDecision: String, Codable, Equatable, Sendable {
    case allow
    case deny
    case ask
}

public enum GitHubExecutionMode: String, Codable, Equatable, Sendable {
    case off
    case manual
}

public struct PermissionPolicy: Codable, Equatable, Sendable {
    public let testCreation: PermissionDecision
    public let testModification: PermissionDecision
    public let localTestExecution: PermissionDecision
    public let githubExecution: GitHubExecutionMode
    public let uiTests: PermissionDecision
    public let simulatorOrDevice: PermissionDecision
    public let performanceOrInstruments: PermissionDecision

    public init(
        testCreation: PermissionDecision,
        testModification: PermissionDecision,
        localTestExecution: PermissionDecision,
        githubExecution: GitHubExecutionMode,
        uiTests: PermissionDecision,
        simulatorOrDevice: PermissionDecision,
        performanceOrInstruments: PermissionDecision
    ) {
        self.testCreation = testCreation
        self.testModification = testModification
        self.localTestExecution = localTestExecution
        self.githubExecution = githubExecution
        self.uiTests = uiTests
        self.simulatorOrDevice = simulatorOrDevice
        self.performanceOrInstruments = performanceOrInstruments
    }
}

public struct SandboxPaths: Codable, Sendable {
    public let root: String
    public let cache: String
}
