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
        EvidenceExpectationDocument(context: try EvidenceProductionContextLoader.load(from: url))
    }

    public static func decode(_ data: Data) throws -> EvidenceExpectationDocument {
        EvidenceExpectationDocument(context: try EvidenceProductionContextLoader.decode(data))
    }
}
