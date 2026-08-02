import CryptoKit
import Darwin
import Foundation

public struct EvidenceArtifactHashingError: Error, Equatable, Sendable {
    public enum Code: String, Sendable {
        case tooManyArtifacts = "TOO_MANY_ARTIFACTS"
        case duplicatePath = "DUPLICATE_PATH"
        case invalidPath = "INVALID_PATH"
        case repositoryRootUnavailable = "REPOSITORY_ROOT_UNAVAILABLE"
        case artifactUnavailable = "ARTIFACT_UNAVAILABLE"
        case artifactNotRegularFile = "ARTIFACT_NOT_REGULAR_FILE"
        case artifactTooLarge = "ARTIFACT_TOO_LARGE"
        case artifactReadFailure = "ARTIFACT_READ_FAILURE"
        case artifactChangedDuringRead = "ARTIFACT_CHANGED_DURING_READ"
    }

    public let code: Code
    public let path: String?

    public init(code: Code, path: String? = nil) {
        self.code = code
        self.path = path
    }
}

public enum EvidenceArtifactHasher {
    public static let maximumArtifactCount = 64
    public static let maximumArtifactBytes = 64 * 1_024 * 1_024

    public static func hash(
        relativePaths: [String],
        repositoryRoot: URL
    ) throws -> [EvidenceArtifact] {
        try hash(
            relativePaths: relativePaths,
            repositoryRoot: repositoryRoot,
            beforeFinalPathValidation: nil
        )
    }

    static func hash(
        relativePaths: [String],
        repositoryRoot: URL,
        beforeFinalPathValidation: ((String, Int32) throws -> Void)?
    ) throws -> [EvidenceArtifact] {
        guard relativePaths.count <= maximumArtifactCount else {
            throw EvidenceArtifactHashingError(code: .tooManyArtifacts)
        }
        let validatedPaths = try relativePaths.map { path -> (String, [String]) in
            guard path.unicodeScalars.prefix(1_025).count <= 1_024 else {
                throw EvidenceArtifactHashingError(code: .invalidPath)
            }
            guard let components = validatedComponents(for: path) else {
                throw EvidenceArtifactHashingError(code: .invalidPath, path: path)
            }
            return (path, components)
        }
        guard Set(validatedPaths.map(\.0)).count == validatedPaths.count else {
            throw EvidenceArtifactHashingError(code: .duplicatePath)
        }
        let sortedPaths = validatedPaths.sorted { $0.0 < $1.0 }

        guard !sortedPaths.isEmpty else {
            return []
        }

        let rootDescriptor = Darwin.open(
            repositoryRoot.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard rootDescriptor >= 0 else {
            throw EvidenceArtifactHashingError(code: .repositoryRootUnavailable)
        }
        defer { Darwin.close(rootDescriptor) }

        return try sortedPaths.map { path, components in
            let artifact = try openArtifact(
                components: components,
                path: path,
                rootDescriptor: rootDescriptor
            )
            defer {
                Darwin.close(artifact.descriptor)
                Darwin.close(artifact.parentDescriptor)
            }

            let hash = try sha256(descriptor: artifact.descriptor, path: path)
            try beforeFinalPathValidation?(path, artifact.parentDescriptor)
            try validateCurrentEntry(
                artifact,
                hashedStatus: hash.status,
                path: path
            )

            return EvidenceArtifact(
                path: path,
                sha256: hash.digest
            )
        }
    }

    private static func validatedComponents(for path: String) -> [String]? {
        guard !path.isEmpty,
              !path.hasPrefix("/"),
              !path.hasPrefix("~"),
              !path.contains("\0") else {
            return nil
        }

        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !components.isEmpty,
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            return nil
        }
        return components.map(String.init)
    }

    private static func openArtifact(
        components: [String],
        path: String,
        rootDescriptor: Int32
    ) throws -> OpenArtifact {
        guard let leafName = components.last else {
            throw EvidenceArtifactHashingError(code: .invalidPath, path: path)
        }

        var parentDescriptor = Darwin.fcntl(rootDescriptor, F_DUPFD_CLOEXEC, 0)
        guard parentDescriptor >= 0 else {
            throw EvidenceArtifactHashingError(code: .artifactUnavailable, path: path)
        }

        for component in components.dropLast() {
            let childDescriptor = component.withCString {
                Darwin.openat(
                    parentDescriptor,
                    $0,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
                )
            }
            guard childDescriptor >= 0 else {
                Darwin.close(parentDescriptor)
                throw EvidenceArtifactHashingError(code: .artifactUnavailable, path: path)
            }
            Darwin.close(parentDescriptor)
            parentDescriptor = childDescriptor
        }

        let descriptor = leafName.withCString {
            Darwin.openat(
                parentDescriptor,
                $0,
                O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard descriptor >= 0 else {
            Darwin.close(parentDescriptor)
            throw EvidenceArtifactHashingError(code: .artifactUnavailable, path: path)
        }
        return OpenArtifact(
            descriptor: descriptor,
            parentDescriptor: parentDescriptor,
            leafName: leafName
        )
    }

    private static func sha256(descriptor: Int32, path: String) throws -> ArtifactHash {
        var initialStatus = stat()
        guard fstat(descriptor, &initialStatus) == 0 else {
            throw EvidenceArtifactHashingError(code: .artifactReadFailure, path: path)
        }
        guard initialStatus.st_mode & S_IFMT == S_IFREG else {
            throw EvidenceArtifactHashingError(code: .artifactNotRegularFile, path: path)
        }
        guard initialStatus.st_size >= 0,
              initialStatus.st_size <= off_t(maximumArtifactBytes) else {
            throw EvidenceArtifactHashingError(code: .artifactTooLarge, path: path)
        }

        var hasher = SHA256()
        var bytesRead = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)

        while true {
            let readCount = buffer.withUnsafeMutableBytes { bytes in
                Darwin.read(descriptor, bytes.baseAddress, bytes.count)
            }
            if readCount == 0 {
                break
            }
            if readCount < 0 {
                if errno == EINTR {
                    continue
                }
                throw EvidenceArtifactHashingError(code: .artifactReadFailure, path: path)
            }

            bytesRead += readCount
            guard bytesRead <= maximumArtifactBytes else {
                throw EvidenceArtifactHashingError(code: .artifactTooLarge, path: path)
            }
            hasher.update(data: buffer.prefix(readCount))
        }

        var finalStatus = stat()
        guard fstat(descriptor, &finalStatus) == 0 else {
            throw EvidenceArtifactHashingError(code: .artifactReadFailure, path: path)
        }
        guard off_t(bytesRead) == initialStatus.st_size,
              sameIdentityAndContents(initialStatus, finalStatus) else {
            throw EvidenceArtifactHashingError(code: .artifactChangedDuringRead, path: path)
        }

        return ArtifactHash(
            digest: hasher.finalize().map { String(format: "%02x", $0) }.joined(),
            status: finalStatus
        )
    }

    private static func validateCurrentEntry(
        _ artifact: OpenArtifact,
        hashedStatus: stat,
        path: String
    ) throws {
        var descriptorStatus = stat()
        var entryStatus = stat()
        let entryStatusResult = artifact.leafName.withCString {
            Darwin.fstatat(
                artifact.parentDescriptor,
                $0,
                &entryStatus,
                AT_SYMLINK_NOFOLLOW
            )
        }
        guard fstat(artifact.descriptor, &descriptorStatus) == 0,
              entryStatusResult == 0,
              sameIdentityAndContents(hashedStatus, descriptorStatus),
              sameIdentityAndContents(hashedStatus, entryStatus) else {
            throw EvidenceArtifactHashingError(code: .artifactChangedDuringRead, path: path)
        }
    }

    private static func sameIdentityAndContents(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev
            && lhs.st_ino == rhs.st_ino
            && lhs.st_size == rhs.st_size
            && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
            && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
            && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec
            && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }

    private struct OpenArtifact {
        let descriptor: Int32
        let parentDescriptor: Int32
        let leafName: String
    }

    private struct ArtifactHash {
        let digest: String
        let status: stat
    }
}
