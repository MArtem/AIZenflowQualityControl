import Foundation

final class UnsafeState: @unchecked Sendable {
    nonisolated(unsafe) var value = 0
}

@preconcurrency import Foundation
