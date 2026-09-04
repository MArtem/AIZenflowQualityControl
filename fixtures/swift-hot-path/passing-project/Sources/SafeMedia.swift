import Foundation

struct SafeMedia {
    func read(_ url: URL) async throws -> Data {
        try await Task.detached(priority: nil) {
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            return try handle.readToEnd() ?? Data()
        }.value
    }
}
