import CryptoKit
import Foundation

package struct XcodeBuildLogMembershipObservation: Equatable, Sendable {
    package static let logSchemaVersion = "0.1.0"

    package let buildLogSHA256: String
    package let compiledSourcePaths: [String]
    package let compilerSectionCount: Int
}

package enum XcodeBuildLogMembershipError: Error, Equatable {
    case documentTooLarge
    case malformedDocument
    case collectionLimitExceeded
    case repositoryPathEscapesRoot
    case unresolvedCompilerInputList
    case unresolvedCompilerInputPath
    case noCompiledSources
    case uncoveredRepositoryInputs([String])
}

/// Extracts repository-owned inputs from Xcode's versioned structured build log.
///
/// The extractor does not authenticate a result bundle or prove that a build succeeded. The future
/// build-evidence boundary must observe those facts and invoke this type in the same authenticated
/// execution before it may remove the source-membership blocker.
package enum XcodeBuildLogMembershipExtractor {
    package static let maximumDocumentBytes = 32 * 1_024 * 1_024
    private static let maximumSections = 100_000
    private static let maximumRepositoryInputs = 100_000
    private static let maximumCommandBytes = 8 * 1_024 * 1_024
    private static let compiledSourceExtensions: Set<String> = [
        "c", "cc", "cpp", "cxx", "m", "metal", "mm", "swift"
    ]

    package static func extract(
        logData: Data,
        repositoryRoot: URL,
        sourcePaths: [String]
    ) throws -> XcodeBuildLogMembershipObservation {
        guard logData.count <= maximumDocumentBytes else {
            throw XcodeBuildLogMembershipError.documentTooLarge
        }
        do {
            try JSONDocumentConstraints.rejectDuplicateObjectKeys(in: logData)
        } catch {
            throw XcodeBuildLogMembershipError.malformedDocument
        }

        let rootSection: BuildLogSection
        do {
            rootSection = try JSONDecoder().decode(BuildLogSection.self, from: logData)
        } catch {
            throw XcodeBuildLogMembershipError.malformedDocument
        }

        let canonicalRoot = repositoryRoot.resolvingSymlinksInPath().standardizedFileURL
        let sourceScopes = try sourcePaths.map { path -> URL in
            guard let resolved = ProfileValidator.resolve(relativePath: path, under: canonicalRoot),
                  ProfileValidator.resolvesWithinRepository(
                      resolved,
                      root: canonicalRoot,
                      allowingRoot: true
                  ) else {
                throw XcodeBuildLogMembershipError.repositoryPathEscapesRoot
            }
            return resolved.resolvingSymlinksInPath().standardizedFileURL
        }

        var sections = [rootSection]
        var visitedSectionCount = 0
        var commandByteCount = 0
        var repositoryInputs = Set<String>()
        var compiledSources = Set<String>()
        var compilerSectionCount = 0

        while let section = sections.popLast() {
            visitedSectionCount += 1
            guard visitedSectionCount <= maximumSections else {
                throw XcodeBuildLogMembershipError.collectionLimitExceeded
            }
            sections.append(contentsOf: section.subsections)

            var sectionInputs = Set<String>()
            if let command = section.commandInvocationDetails?.commandDetails {
                commandByteCount += command.utf8.count
                guard commandByteCount <= maximumCommandBytes else {
                    throw XcodeBuildLogMembershipError.collectionLimitExceeded
                }
                let words = try ShellWords.tokenize(command)
                guard let compilerCommandKind = compilerCommandKind(words) else {
                    continue
                }
                compilerSectionCount += 1
                for word in words {
                    guard compilerCommandKind == .structured
                        || !isUnresolvedCompilerInputList(word) else {
                        throw XcodeBuildLogMembershipError.unresolvedCompilerInputList
                    }
                    try appendCommandWord(
                        word,
                        canonicalRoot: canonicalRoot,
                        to: &sectionInputs,
                        rejectsRelativeSource: compilerCommandKind == .raw
                    )
                }
                try appendLocation(
                    section.location,
                    canonicalRoot: canonicalRoot,
                    to: &sectionInputs
                )
                for message in section.messages {
                    try appendLocation(
                        message.location,
                        canonicalRoot: canonicalRoot,
                        to: &sectionInputs
                    )
                    for annotation in message.annotations {
                        try appendLocation(
                            annotation.location,
                            canonicalRoot: canonicalRoot,
                            to: &sectionInputs
                        )
                    }
                }
            }

            compiledSources.formUnion(sectionInputs)
            repositoryInputs.formUnion(sectionInputs)
            guard repositoryInputs.count <= maximumRepositoryInputs else {
                throw XcodeBuildLogMembershipError.collectionLimitExceeded
            }
        }

        guard !compiledSources.isEmpty, compilerSectionCount > 0 else {
            throw XcodeBuildLogMembershipError.noCompiledSources
        }

        let uncovered = repositoryInputs.filter { relativePath in
            let input = canonicalRoot
                .appendingPathComponent(relativePath)
                .resolvingSymlinksInPath()
                .standardizedFileURL
            return !sourceScopes.contains(where: { scope in
                ProfileValidator.resolvesWithinRepository(
                    input,
                    root: scope,
                    allowingRoot: true
                )
            })
        }.sorted(by: bytewiseLessThan)
        guard uncovered.isEmpty else {
            throw XcodeBuildLogMembershipError.uncoveredRepositoryInputs(
                Array(uncovered.prefix(256))
            )
        }

        return XcodeBuildLogMembershipObservation(
            buildLogSHA256: SHA256.hash(data: logData).map {
                String(format: "%02x", $0)
            }.joined(),
            compiledSourcePaths: compiledSources.sorted(by: bytewiseLessThan),
            compilerSectionCount: compilerSectionCount
        )
    }

    private static func appendLocation(
        _ location: BuildLogLocation?,
        canonicalRoot: URL,
        to paths: inout Set<String>
    ) throws {
        guard let rawURL = location?.url else {
            return
        }
        let candidate: URL?
        if let url = URL(string: rawURL), url.isFileURL {
            candidate = url
        } else if rawURL.hasPrefix("/") {
            candidate = URL(fileURLWithPath: rawURL)
        } else {
            candidate = nil
        }
        if let candidate,
           let relativePath = try repositoryRelativePath(
               candidate,
               canonicalRoot: canonicalRoot
           ),
           isCompiledSource(relativePath) {
            paths.insert(relativePath)
        }
    }

    private static func appendCommandWord(
        _ word: String,
        canonicalRoot: URL,
        to paths: inout Set<String>,
        rejectsRelativeSource: Bool
    ) throws {
        var candidates = [word]
        if word.hasPrefix("@") {
            candidates.append(String(word.dropFirst()))
        }
        if let separator = word.firstIndex(of: "=") {
            candidates.append(String(word[word.index(after: separator)...]))
        }

        for rawCandidate in candidates {
            guard looksLikeCompiledSource(rawCandidate) else {
                continue
            }
            guard let rootRange = rawCandidate.range(of: canonicalRoot.path) else {
                if rejectsRelativeSource && !rawCandidate.hasPrefix("/") {
                    throw XcodeBuildLogMembershipError.unresolvedCompilerInputPath
                }
                continue
            }
            var path = String(rawCandidate[rootRange.lowerBound...])
            while let scalar = path.unicodeScalars.last,
                  scalar == "," || scalar == ")" || scalar == "]" || scalar == "}" {
                path.unicodeScalars.removeLast()
            }
            if let relativePath = try repositoryRelativePath(
                URL(fileURLWithPath: path),
                canonicalRoot: canonicalRoot
            ) {
                paths.insert(relativePath)
            }
        }
    }

    private static func repositoryRelativePath(
        _ candidate: URL,
        canonicalRoot: URL
    ) throws -> String? {
        let standardizedCandidate = candidate.standardizedFileURL
        let lexicalRoot = canonicalRoot.path
        let lexicalPath = standardizedCandidate.path
        guard lexicalPath == lexicalRoot || lexicalPath.hasPrefix(lexicalRoot + "/") else {
            return nil
        }

        let resolvedCandidate = standardizedCandidate
            .resolvingSymlinksInPath()
            .standardizedFileURL
        guard ProfileValidator.resolvesWithinRepository(
            resolvedCandidate,
            root: canonicalRoot,
            allowingRoot: true
        ) else {
            throw XcodeBuildLogMembershipError.repositoryPathEscapesRoot
        }
        guard resolvedCandidate.path != canonicalRoot.path else {
            return nil
        }
        return String(resolvedCandidate.path.dropFirst(canonicalRoot.path.count + 1))
    }

    private static func isCompiledSource(_ relativePath: String) -> Bool {
        compiledSourceExtensions.contains(
            URL(fileURLWithPath: relativePath).pathExtension.lowercased()
        )
    }

    private static func looksLikeCompiledSource(_ word: String) -> Bool {
        let trimmed = word.trimmingCharacters(in: CharacterSet(charactersIn: ",)]}"))
        return isCompiledSource(trimmed)
    }

    private enum CompilerCommandKind {
        case raw
        case structured
    }

    private static func compilerCommandKind(_ words: [String]) -> CompilerCommandKind? {
        guard let firstWord = words.first else {
            return nil
        }
        if firstWord == "SwiftCompile" || firstWord == "CompileC" {
            return .structured
        }
        if firstWord == "Ld" {
            return nil
        }
        if words.contains(where: { word in
            let executable = URL(fileURLWithPath: word).lastPathComponent
            return executable.hasPrefix("builtin-Swift")
        }) {
            return nil
        }
        let compilerExecutables: Set<String> = [
            "clang", "clang++", "gcc", "metal", "metalfe", "swift-frontend", "swiftc"
        ]
        return words.contains { word in
            compilerExecutables.contains(URL(fileURLWithPath: word).lastPathComponent.lowercased())
        } ? .raw : nil
    }

    private static func isUnresolvedCompilerInputList(_ word: String) -> Bool {
        let lowercased = word.lowercased()
        if lowercased.hasPrefix("@/") {
            return true
        }
        return lowercased.contains(".swiftfilelist")
            || lowercased.contains(".swiftconstvaluesfilelist")
            || lowercased.hasSuffix(".resp")
            || lowercased.hasSuffix(".rsp")
    }

    private static func bytewiseLessThan(_ lhs: String, _ rhs: String) -> Bool {
        lhs.utf8.lexicographicallyPrecedes(rhs.utf8)
    }
}

private enum ShellWords {
    private enum State {
        case normal
        case singleQuoted
        case doubleQuoted
        case escapedNormal
        case escapedDouble
    }

    static func tokenize(_ command: String) throws -> [String] {
        var state = State.normal
        var words: [String] = []
        var current = String.UnicodeScalarView()

        func finishWord() {
            guard !current.isEmpty else {
                return
            }
            words.append(String(current))
            current.removeAll(keepingCapacity: true)
        }

        for scalar in command.unicodeScalars {
            switch state {
            case .normal:
                if scalar == " " || scalar == "\t" || scalar == "\n" || scalar == "\r" {
                    finishWord()
                } else if scalar == "'" {
                    state = .singleQuoted
                } else if scalar == "\"" {
                    state = .doubleQuoted
                } else if scalar == "\\" {
                    state = .escapedNormal
                } else {
                    current.append(scalar)
                }
            case .singleQuoted:
                if scalar == "'" {
                    state = .normal
                } else {
                    current.append(scalar)
                }
            case .doubleQuoted:
                if scalar == "\"" {
                    state = .normal
                } else if scalar == "\\" {
                    state = .escapedDouble
                } else {
                    current.append(scalar)
                }
            case .escapedNormal:
                current.append(scalar)
                state = .normal
            case .escapedDouble:
                current.append(scalar)
                state = .doubleQuoted
            }
        }
        guard state == .normal else {
            throw XcodeBuildLogMembershipError.malformedDocument
        }
        finishWord()
        return words
    }
}

private struct BuildLogSection: Decodable {
    let location: BuildLogLocation?
    let subsections: [BuildLogSection]
    let messages: [BuildLogMessage]
    let commandInvocationDetails: BuildLogCommandInvocation?

    private enum CodingKeys: String, CodingKey {
        case location
        case subsections
        case messages
        case commandInvocationDetails
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        location = try container.decodeIfPresent(BuildLogLocation.self, forKey: .location)
        subsections = try container.decodeIfPresent(
            [BuildLogSection].self,
            forKey: .subsections
        ) ?? []
        messages = try container.decodeIfPresent(
            [BuildLogMessage].self,
            forKey: .messages
        ) ?? []
        commandInvocationDetails = try container.decodeIfPresent(
            BuildLogCommandInvocation.self,
            forKey: .commandInvocationDetails
        )
    }
}

private struct BuildLogLocation: Decodable {
    let url: String?
}

private struct BuildLogCommandInvocation: Decodable {
    let commandDetails: String?
}

private struct BuildLogMessage: Decodable {
    let location: BuildLogLocation?
    let annotations: [BuildLogAnnotation]

    private enum CodingKeys: String, CodingKey {
        case location
        case annotations
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        location = try container.decodeIfPresent(BuildLogLocation.self, forKey: .location)
        annotations = try container.decodeIfPresent(
            [BuildLogAnnotation].self,
            forKey: .annotations
        ) ?? []
    }
}

private struct BuildLogAnnotation: Decodable {
    let location: BuildLogLocation?
}
