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
    // Leave one MiB for the response envelope, input digests, and profile/policy checks.
    private static let maximumEncodedManifestCheckBytes =
        StaticWorkerBoundary.maximumOutputBytes - 1_024 * 1_024

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
        var filesystemEquivalentPaths = Set<String>()
        var parsed: [Entry] = []
        parsed.reserveCapacity(records.count)
        for record in records {
            let sections = record.split(separator: "\t", maxSplits: 1, omittingEmptySubsequences: false)
            guard sections.count == 2,
                  let path = Self.validatePath(String(sections[1])),
                  paths.insert(path).inserted,
                  filesystemEquivalentPaths.insert(
                    path.precomposedStringWithCanonicalMapping.lowercased()
                  ).inserted else {
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

    package func staticChecks(
        sourcePaths: [String],
        maximumFileBytes: Int,
        excludedDirectoryNames: Set<String>,
        forbiddenFileSuffixes: [String]
    ) -> [QualityCheck] {
        guard !sourcePaths.isEmpty,
              sourcePaths.allSatisfy({ Self.validatePath($0) != nil }) else {
            return [QualityCheck(id: "QC.STATIC.SOURCE_PATH", status: .blocked, message: "Configured source paths are invalid.")]
        }
        let forbidden = forbiddenFileSuffixes.map { $0.lowercased() }
        var checks: [QualityCheck] = []
        var encodedCheckBytes = 0
        var regularFiles = 0
        // The worker adds a profile check, a policy check, and this scanner's limit check.
        let maximumFindings = StaticEvidenceResultLimits.maximumChecks - 3
        var limitReached = false

        func appendFinding(_ check: QualityCheck) -> Bool {
            guard checks.count < maximumFindings,
                  let encodedBytes = try? JSONEncoder().encode(check).count,
                  encodedCheckBytes + encodedBytes <= Self.maximumEncodedManifestCheckBytes else {
                return false
            }
            checks.append(check)
            encodedCheckBytes += encodedBytes
            return true
        }

        sourceLoop: for sourcePath in sourcePaths.sorted() {
            let prefix = sourcePath == "." ? "" : sourcePath + "/"
            let scoped = entries.filter { prefix.isEmpty || $0.path.hasPrefix(prefix) }
            guard !scoped.isEmpty else {
                guard appendFinding(QualityCheck(id: "QC.STATIC.SOURCE_PATH", status: .blocked, message: "Configured source path has no Git-tree entries.", path: sourcePath)) else {
                    limitReached = true
                    break sourceLoop
                }
                continue
            }
            for entry in scoped {
                let components = entry.path.split(separator: "/").map(String.init)
                if components.contains(where: { component in
                    forbidden.contains { component.lowercased().hasSuffix($0) }
                }) {
                    guard appendFinding(QualityCheck(id: "QC.STATIC.FORBIDDEN_ARTIFACT", status: .fail, message: "Generated or release artifact is forbidden in source scope.", path: entry.path)) else {
                        limitReached = true
                        break sourceLoop
                    }
                }
                guard !components.dropLast().contains(where: { excludedDirectoryNames.contains($0) }) else { continue }
                switch entry.kind {
                case .symlink:
                    guard appendFinding(QualityCheck(id: "QC.STATIC.SYMLINK_REQUIRES_REVIEW", status: .blocked, message: "Symbolic links require explicit boundary review.", path: entry.path)) else {
                        limitReached = true
                        break sourceLoop
                    }
                case .file:
                    regularFiles += 1
                    if entry.size > Int64(maximumFileBytes) {
                        guard appendFinding(QualityCheck(id: "QC.STATIC.OVERSIZED_FILE", status: .fail, message: "File exceeds the configured maximum byte size.", path: entry.path)) else {
                            limitReached = true
                            break sourceLoop
                        }
                    }
                }
            }
        }
        if limitReached {
            checks.append(QualityCheck(id: "QC.STATIC.SCAN_LIMIT_REACHED", status: .blocked, message: "Static manifest scan stopped at the public evidence finding limit."))
            return checks
        }
        if checks.contains(where: { $0.status != .pass }) { return checks }
        if regularFiles == 0 {
            return [QualityCheck(id: "QC.STATIC.NO_FILES_SCANNED", status: .blocked, message: "Static scan inspected zero regular files.")]
        }
        return [QualityCheck(id: "QC.STATIC.SCAN", status: .pass, message: "Static scan completed for \(regularFiles) regular files.")]
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

}
