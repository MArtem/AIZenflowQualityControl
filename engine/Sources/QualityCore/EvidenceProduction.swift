import Foundation

private struct EvidenceProductionCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil

    init?(stringValue: String) {
        self.stringValue = stringValue
    }

    init?(intValue: Int) {
        return nil
    }
}

private func rejectUnknownProductionKeys(
    from decoder: Decoder,
    allowed: Set<String>
) throws {
    let container = try decoder.container(keyedBy: EvidenceProductionCodingKey.self)
    guard container.allKeys.allSatisfy({ allowed.contains($0.stringValue) }) else {
        throw DecodingError.dataCorrupted(
            DecodingError.Context(
                codingPath: decoder.codingPath,
                debugDescription: "Evidence production context contains an unknown property."
            )
        )
    }
}

private func rejectNullProductionValue<Key: CodingKey>(
    in container: KeyedDecodingContainer<Key>,
    forKey key: Key
) throws {
    guard try !container.decodeNil(forKey: key) else {
        throw DecodingError.valueNotFound(
            String.self,
            DecodingError.Context(
                codingPath: container.codingPath + [key],
                debugDescription: "Evidence production context optional properties must be omitted rather than null."
            )
        )
    }
}

private func decodeOptionalProductionValue<Value: Decodable, Key: CodingKey>(
    _ type: Value.Type,
    from container: KeyedDecodingContainer<Key>,
    forKey key: Key
) throws -> Value? {
    guard container.contains(key) else {
        return nil
    }
    try rejectNullProductionValue(in: container, forKey: key)
    return try container.decode(Value.self, forKey: key)
}

public struct EvidenceProductionContext: Sendable {
    public let sourceRepository: String
    public let sourceRevision: String
    public let engineVersion: String
    public let engineRevision: String
    public let toolchain: EvidenceToolchain
    public let commands: [EvidenceCommand]
    public let gates: [EvidenceGate]
    public let testCounts: EvidenceTestCounts?
    public let testGateID: String?
    public let reviewRevision: String?
    public let residualRisks: [String]

    public init(
        sourceRepository: String,
        sourceRevision: String,
        engineVersion: String,
        engineRevision: String,
        toolchain: EvidenceToolchain,
        commands: [EvidenceCommand],
        gates: [EvidenceGate],
        testCounts: EvidenceTestCounts? = nil,
        testGateID: String? = nil,
        reviewRevision: String? = nil,
        residualRisks: [String] = []
    ) {
        self.sourceRepository = sourceRepository
        self.sourceRevision = sourceRevision
        self.engineVersion = engineVersion
        self.engineRevision = engineRevision
        self.toolchain = toolchain
        self.commands = commands
        self.gates = gates
        self.testCounts = testCounts
        self.testGateID = testGateID
        self.reviewRevision = reviewRevision
        self.residualRisks = residualRisks
    }
}

public enum EvidenceProductionContextLoader {
    public static let maximumDocumentBytes = 1_000_000

    public static func load(from url: URL) throws -> EvidenceProductionContext {
        try decode(
            JSONDocumentConstraints.loadData(
                from: url,
                maximumBytes: maximumDocumentBytes
            )
        )
    }

    public static func decode(_ data: Data) throws -> EvidenceProductionContext {
        guard data.count <= maximumDocumentBytes else {
            throw EvidenceProductionDocumentLimitError()
        }
        try JSONDocumentConstraints.rejectDuplicateObjectKeys(in: data)
        return try JSONDecoder().decode(EvidenceProductionDocument.self, from: data).context
    }
}

public enum EvidenceProductionError: Error, Equatable {
    case invalidContext([EvidenceVerificationIssue])
    case invalidProfile([ValidationIssue])
}

public enum EvidenceProducer {
    public static func produce(
        context: EvidenceProductionContext,
        profileSnapshot: ProfileSnapshot,
        userAuthorizedActions: Set<PermissionAction> = []
    ) throws -> QualityEvidence {
        let profileIssues = ProfileValidator.validate(profileSnapshot.profile)
        guard profileIssues.isEmpty else {
            throw EvidenceProductionError.invalidProfile(profileIssues)
        }
        try validateContextBounds(context)
        let evidence = QualityEvidence(
            sourceRepository: context.sourceRepository,
            sourceRevision: context.sourceRevision,
            engineVersion: context.engineVersion,
            engineRevision: context.engineRevision,
            profileSchemaVersion: profileSnapshot.profile.schemaVersion,
            profileSHA256: profileSnapshot.sha256,
            toolchain: context.toolchain,
            permissions: profileSnapshot.profile.permissions,
            commands: context.commands,
            gates: context.gates,
            testCounts: context.testCounts,
            reviewRevision: context.reviewRevision,
            artifacts: [],
            residualRisks: context.residualRisks,
            claimedVerdict: EvidenceVerifier.derive(
                gates: context.gates,
                residualRisks: context.residualRisks
            )
        )
        let verification = EvidenceVerifier.verify(
            evidence,
            expected: expectation(
                for: context,
                profileSnapshot: profileSnapshot,
                userAuthorizedActions: userAuthorizedActions
            )
        )
        guard verification.issues.isEmpty else {
            throw EvidenceProductionError.invalidContext(verification.issues)
        }
        return evidence
    }

    static func expectation(
        for context: EvidenceProductionContext,
        profileSnapshot: ProfileSnapshot,
        userAuthorizedActions: Set<PermissionAction> = []
    ) -> EvidenceExpectation {
        var commandsByID: [String: EvidenceCommandExpectation] = [:]
        for command in context.commands where commandsByID[command.id] == nil {
            commandsByID[command.id] = EvidenceCommandExpectation(
                commandSHA256: command.commandSHA256,
                exitCode: command.exitCode,
                actions: Set(command.actions)
            )
        }
        var gatesByID: [String: EvidenceGateExpectation] = [:]
        for gate in context.gates where gatesByID[gate.id] == nil {
            gatesByID[gate.id] = EvidenceGateExpectation(
                commandID: gate.commandID,
                actions: Set(gate.actions),
                status: gate.status,
                message: gate.message
            )
        }
        return EvidenceExpectation(
            sourceRepository: context.sourceRepository,
            sourceRevision: context.sourceRevision,
            engineVersion: context.engineVersion,
            engineRevision: context.engineRevision,
            profileSchemaVersion: profileSnapshot.profile.schemaVersion,
            profileSHA256: profileSnapshot.sha256,
            toolchain: context.toolchain,
            permissions: profileSnapshot.profile.permissions,
            commandsByID: commandsByID,
            gatesByID: gatesByID,
            userAuthorizedActions: userAuthorizedActions,
            testCounts: context.testCounts,
            testGateID: context.testGateID,
            reviewRevision: context.reviewRevision,
            artifactSHA256ByPath: [:],
            residualRisks: Set(context.residualRisks)
        )
    }

    private static func validateContextBounds(
        _ context: EvidenceProductionContext
    ) throws {
        let maximumItems = 64
        guard context.commands.count <= maximumItems,
              context.gates.count <= maximumItems,
              context.residualRisks.count <= maximumItems else {
            throw EvidenceProductionError.invalidContext([
                EvidenceVerificationIssue(
                    code: "QC.EVIDENCE.COLLECTION_LIMIT",
                    message: "Evidence production context exceeds the collection limit."
                )
            ])
        }
    }
}

private struct EvidenceProductionDocument: Decodable {
    let sourceRepository: String
    let sourceRevision: String
    let engineVersion: String
    let engineRevision: String
    let toolchain: EvidenceToolchain
    let commands: [EvidenceCommand]
    let gates: [EvidenceGate]
    let testCounts: EvidenceTestCounts?
    let testGateID: String?
    let reviewRevision: String?
    let residualRisks: [String]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case sourceRepository
        case sourceRevision
        case engineVersion
        case engineRevision
        case toolchain
        case commands
        case gates
        case testCounts
        case testGateID
        case reviewRevision
        case residualRisks
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownProductionKeys(
            from: decoder,
            allowed: Set(CodingKeys.allCases.map(\.rawValue))
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sourceRepository = try container.decode(String.self, forKey: .sourceRepository)
        sourceRevision = try container.decode(String.self, forKey: .sourceRevision)
        engineVersion = try container.decode(String.self, forKey: .engineVersion)
        engineRevision = try container.decode(String.self, forKey: .engineRevision)
        toolchain = try container.decode(EvidenceToolchain.self, forKey: .toolchain)
        commands = try container.decode([EvidenceCommand].self, forKey: .commands)
        gates = try container.decode([EvidenceGate].self, forKey: .gates)
        testCounts = try decodeOptionalProductionValue(
            EvidenceTestCounts.self,
            from: container,
            forKey: .testCounts
        )
        testGateID = try decodeOptionalProductionValue(String.self, from: container, forKey: .testGateID)
        reviewRevision = try decodeOptionalProductionValue(
            String.self,
            from: container,
            forKey: .reviewRevision
        )
        residualRisks = try container.decode([String].self, forKey: .residualRisks)
    }

    var context: EvidenceProductionContext {
        EvidenceProductionContext(
            sourceRepository: sourceRepository,
            sourceRevision: sourceRevision,
            engineVersion: engineVersion,
            engineRevision: engineRevision,
            toolchain: toolchain,
            commands: commands,
            gates: gates,
            testCounts: testCounts,
            testGateID: testGateID,
            reviewRevision: reviewRevision,
            residualRisks: residualRisks
        )
    }
}

private struct EvidenceProductionDocumentLimitError: Error {}
