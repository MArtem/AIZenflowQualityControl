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

public enum ProjectMode: String, Codable, Sendable {
    case prototype
    case controlled
    case production
}

public enum PermissionDecision: String, Codable, Sendable {
    case allow
    case deny
    case ask
}

public enum GitHubExecutionMode: String, Codable, Sendable {
    case off
    case manual
}

public struct PermissionPolicy: Codable, Sendable {
    public let testCreation: PermissionDecision
    public let testModification: PermissionDecision
    public let localTestExecution: PermissionDecision
    public let githubExecution: GitHubExecutionMode
    public let uiTests: PermissionDecision
    public let simulatorOrDevice: PermissionDecision
    public let performanceOrInstruments: PermissionDecision
}

public struct SandboxPaths: Codable, Sendable {
    public let root: String
    public let cache: String
}
