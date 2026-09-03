import Foundation

/// A bounded, untrusted expectation-shaped document.
///
/// Successful loading proves only syntax and the closed document envelope. It never grants the
/// document authority to construct `EvidenceExpectation`; a future trusted execution coordinator
/// must establish that authority outside this loader.
public struct EvidenceExpectationDocument: Sendable {
    public let context: EvidenceProductionContext

    fileprivate init(context: EvidenceProductionContext) {
        self.context = context
    }
}

public enum EvidenceExpectationDocumentLoader {
    public static let maximumDocumentBytes = EvidenceProductionContextLoader.maximumDocumentBytes

    public static func load(from url: URL) throws -> EvidenceExpectationDocument {
        try validated(EvidenceProductionContextLoader.load(from: url))
    }

    public static func decode(_ data: Data) throws -> EvidenceExpectationDocument {
        try validated(EvidenceProductionContextLoader.decode(data))
    }

    private static func validated(_ context: EvidenceProductionContext) throws -> EvidenceExpectationDocument {
        let commands = context.commands
        let gates = context.gates
        guard !gates.isEmpty,
              commands.count <= 64,
              gates.count <= 64,
              context.residualRisks.count <= 64,
              EvidenceVerifier.isBoundedNonEmptyString(context.sourceRepository),
              EvidenceVerifier.isBoundedNonEmptyString(context.engineVersion),
              EvidenceVerifier.isBoundedNonEmptyString(context.toolchain.swiftVersion),
              EvidenceVerifier.isBoundedNonEmptyString(context.toolchain.xcodeVersion),
              isRevision(context.sourceRevision), isRevision(context.engineRevision),
              Set(commands.map(\.id)).count == commands.count,
              Set(gates.map(\.id)).count == gates.count,
              Set(context.residualRisks).count == context.residualRisks.count,
              commands.allSatisfy({ command in
                  EvidenceVerifier.isBoundedNonEmptyString(command.id)
                      && isHash(command.commandSHA256)
                      && command.actions.count <= PermissionAction.allCases.count
                      && Set(command.actions).count == command.actions.count
              }),
              gates.allSatisfy({ gate in
                  EvidenceVerifier.isBoundedNonEmptyString(gate.id)
                      && EvidenceVerifier.isBoundedNonEmptyString(gate.message)
                      && gate.actions.count <= PermissionAction.allCases.count
                      && Set(gate.actions).count == gate.actions.count
                      && gate.commandID.map(EvidenceVerifier.isBoundedNonEmptyString) != false
              }),
              context.residualRisks.allSatisfy(EvidenceVerifier.isBoundedNonEmptyString) else {
            throw EvidenceExpectationDocumentValidationError()
        }
        let commandIDs = Set(commands.map(\.id))
        guard gates.allSatisfy({ gate in
            guard let commandID = gate.commandID else {
                return gate.status != .pass && gate.status != .fail
            }
            return commandIDs.contains(commandID)
        }) else {
            throw EvidenceExpectationDocumentValidationError()
        }
        return EvidenceExpectationDocument(context: context)
    }

    private static func isRevision(_ value: String) -> Bool { isHex(value, count: 40) }
    private static func isHash(_ value: String) -> Bool { isHex(value, count: 64) }
    private static func isHex(_ value: String, count: Int) -> Bool {
        value.utf8.count == count
            && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}

private struct EvidenceExpectationDocumentValidationError: Error {}
