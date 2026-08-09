import Darwin
import CryptoKit
import Foundation

package enum GitTreeStaticSnapshotError: Error {
    case invalidManifest
    case limitExceeded
    case materializationFailed
}

/// A bounded, path-validated view of Git tree metadata used by static evidence.
///
/// The current static scanner inspects names, entry kinds, and byte sizes only. Materialization
/// therefore uses sparse placeholders rather than mutable worktree bytes; any future content-aware
/// static rule must extend this provider rather than silently treating placeholders as source text.
package struct GitTreeStaticSnapshot: Sendable {
    package static let maximumManifestBytes = 32 * 1_024 * 1_024
    package static let maximumEntries = 100_000

    private let entries: [Entry]
    package let sha256: String

    package init(manifest: Data) throws {
        guard manifest.count <= Self.maximumManifestBytes else {
            throw GitTreeStaticSnapshotError.limitExceeded
        }
        guard let records = String(data: manifest, encoding: .utf8)?.split(separator: "\0", omittingEmptySubsequences: true) else {
            throw GitTreeStaticSnapshotError.invalidManifest
        }
        guard records.count <= Self.maximumEntries else {
            throw GitTreeStaticSnapshotError.limitExceeded
        }

        var paths = Set<String>()
        var parsed: [Entry] = []
        parsed.reserveCapacity(records.count)
        for record in records {
            let sections = record.split(separator: "\t", maxSplits: 1, omittingEmptySubsequences: false)
            guard sections.count == 2,
                  let path = Self.validatePath(String(sections[1])),
                  paths.insert(path).inserted else {
                throw GitTreeStaticSnapshotError.invalidManifest
            }
            let fields = sections[0].split(whereSeparator: \.isWhitespace)
            guard fields.count == 4,
                  let kind = Kind(mode: String(fields[0]), type: String(fields[1])),
                  Self.isObjectID(String(fields[2])),
                  let size = Int64(fields[3]), size >= 0 else {
                throw GitTreeStaticSnapshotError.invalidManifest
            }
            parsed.append(Entry(path: path, kind: kind, size: size))
        }
        entries = parsed.sorted { $0.path < $1.path }
        sha256 = SHA256.hash(data: manifest).map { String(format: "%02x", $0) }.joined()
    }

    package func materialize(in parent: URL, sourcePaths: [String]) throws -> URL {
        guard !sourcePaths.isEmpty,
              sourcePaths.allSatisfy({ Self.validatePath($0) != nil }) else {
            throw GitTreeStaticSnapshotError.invalidManifest
        }
        var isDirectory = ObjCBool(false)
        guard FileManager.default.fileExists(atPath: parent.path, isDirectory: &isDirectory),
              isDirectory.boolValue else {
            throw GitTreeStaticSnapshotError.materializationFailed
        }

        let root = parent.appendingPathComponent("git-tree-" + UUID().uuidString, isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            for sourcePath in sourcePaths {
                try createDirectory(relativePath: sourcePath, under: root)
            }
            for entry in entries where sourcePaths.contains(where: {
                $0 == "." || entry.path == $0 || entry.path.hasPrefix($0 + "/")
            }) {
                try materialize(entry, under: root)
            }
            return root
        } catch {
            try? Self.makeWritable(root)
            try? FileManager.default.removeItem(at: root)
            throw GitTreeStaticSnapshotError.materializationFailed
        }
    }

    package static func removeMaterialization(at root: URL) throws {
        try makeWritable(root)
        try FileManager.default.removeItem(at: root)
    }

    package static func sealMaterialization(at root: URL) throws {
        try seal(root)
    }

    private struct Entry: Sendable {
        let path: String
        let kind: Kind
        let size: Int64
    }

    private enum Kind: Sendable {
        case file
        case symlink

        init?(mode: String, type: String) {
            switch (mode, type) {
            case ("100644", "blob"), ("100755", "blob"):
                self = .file
            case ("120000", "blob"):
                self = .symlink
            default:
                return nil
            }
        }
    }

    private static func validatePath(_ value: String) -> String? {
        if value == "." {
            return value
        }
        guard !value.isEmpty,
              value.unicodeScalars.count <= StaticEvidenceResultLimits.maximumStringScalars,
              !value.hasPrefix("/") else {
            return nil
        }
        let components = value.split(separator: "/", omittingEmptySubsequences: false)
        guard components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            return nil
        }
        return value
    }

    private static func isObjectID(_ value: String) -> Bool {
        let bytes = value.utf8
        return (bytes.count == 40 || bytes.count == 64) && bytes.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
    }

    private func materialize(_ entry: Entry, under root: URL) throws {
        let url = root.appendingPathComponent(entry.path)
        let parent = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        switch entry.kind {
        case .file:
            guard FileManager.default.createFile(atPath: url.path, contents: Data()) else {
                throw GitTreeStaticSnapshotError.materializationFailed
            }
            let handle = try FileHandle(forWritingTo: url)
            defer { try? handle.close() }
            try handle.truncate(atOffset: UInt64(entry.size))
        case .symlink:
            try FileManager.default.createSymbolicLink(atPath: url.path, withDestinationPath: "git-tree-snapshot")
        }
    }

    private func createDirectory(relativePath: String, under root: URL) throws {
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(relativePath, isDirectory: true),
            withIntermediateDirectories: true
        )
    }

    private static func seal(_ root: URL) throws {
        let manager = FileManager.default
        guard let enumerator = manager.enumerator(at: root, includingPropertiesForKeys: [.isDirectoryKey], options: []) else {
            throw GitTreeStaticSnapshotError.materializationFailed
        }
        for case let url as URL in enumerator {
            let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            guard values.isSymbolicLink != true else { continue }
            guard chmod(url.path, values.isDirectory == true ? 0o500 : 0o400) == 0 else {
                throw GitTreeStaticSnapshotError.materializationFailed
            }
        }
        guard chmod(root.path, 0o500) == 0 else {
            throw GitTreeStaticSnapshotError.materializationFailed
        }
    }

    private static func makeWritable(_ root: URL) throws {
        guard FileManager.default.fileExists(atPath: root.path) else { return }
        _ = chmod(root.path, 0o700)
        if let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey], options: []) {
            for case let url as URL in enumerator {
                let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
                guard values.isSymbolicLink != true else { continue }
                _ = chmod(url.path, values.isDirectory == true ? 0o700 : 0o600)
            }
        }
    }
}
