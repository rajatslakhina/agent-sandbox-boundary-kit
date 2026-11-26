import Foundation

/// Why a path could not be resolved to its physical location.
public enum ResolutionError: Error, Equatable, Sendable {
    case tooManyLinks(String)
    case invalidLinkTarget(String)
}

/// Maps a lexical path to the path the file system would actually open.
///
/// The gate checks containment on BOTH the lexical and the resolved path, so a
/// symlink planted inside a granted root cannot point the agent outside it.
/// Resolution happens at check time: a link swapped between the check and the
/// open (TOCTOU) is outside what this type can prevent. See the README's limits.
public protocol PathResolving: Sendable {
    func resolve(_ path: SandboxPath) throws -> SandboxPath
}

/// No resolution: the lexical path is the physical path. Correct only when the
/// executor never follows links (for example an in-memory store).
public struct LexicalResolver: PathResolving {
    public init() {}
    public func resolve(_ path: SandboxPath) throws -> SandboxPath { path }
}

/// Resolves against an explicit link table. Used by the eval corpus and the demo
/// so a planted symlink is deterministic and needs no real file system.
public struct SymlinkTableResolver: PathResolving {
    public let links: [SandboxPath: SandboxPath]
    public let maxHops: Int

    public init(links: [SandboxPath: SandboxPath], maxHops: Int = 40) {
        self.links = links
        self.maxHops = min(max(1, maxHops), FileSystemResolver.hopLimit)
    }

    public func resolve(_ path: SandboxPath) throws -> SandboxPath {
        var current = path.components
        var hops = 0
        outer: while true {
            // Expand the shortest prefix that is a link, then rescan from the start.
            var length = 1
            while length <= current.count {
                let prefix = SandboxPath(normalisedComponents: Array(current[0..<length]))
                if let target = links[prefix] {
                    hops = hops.saturatingAdd(1)
                    guard hops <= maxHops else { throw ResolutionError.tooManyLinks(path.string) }
                    current = target.components + Array(current[length...])
                    guard current.count <= SandboxPath.maxComponents else {
                        throw ResolutionError.invalidLinkTarget(path.string)
                    }
                    continue outer
                }
                length += 1
            }
            return SandboxPath(normalisedComponents: current)
        }
    }
}

/// Resolves symlinks on the real file system, one component at a time, the way
/// the kernel walks a path. Components that do not exist yet (a file about to be
/// written) are kept literally.
///
/// Link targets are walked raw, not collapsed as text: a `..` inside a target
/// pops the already-resolved (physical) prefix, exactly as the kernel does after
/// following the link. A `..` that would climb above `/` fails closed.
public struct FileSystemResolver: PathResolving {
    /// The most hops any resolver will follow, whatever it is configured with: a
    /// cap near `Int.max` would make a link loop spin effectively forever.
    public static let hopLimit = 255

    public let maxHops: Int

    /// `maxHops` is clamped to `1...hopLimit`.
    public init(maxHops: Int = 40) {
        self.maxHops = min(max(1, maxHops), Self.hopLimit)
    }

    public func resolve(_ path: SandboxPath) throws -> SandboxPath {
        let fileManager = FileManager.default
        var resolved: [String] = []           // physical components so far
        var pending = path.components[...]    // raw components still to walk
        var hops = 0
        var steps = 0
        // Each hop can queue at most 2 * maxComponents raw components, so this bounds the walk.
        let maxSteps = maxHops.saturatingAdd(1).saturatingMultiply(SandboxPath.maxComponents * 2 + 1)

        while let component = pending.first {
            pending = pending.dropFirst()
            steps = steps.saturatingAdd(1)
            guard steps <= maxSteps else { throw ResolutionError.tooManyLinks(path.string) }

            switch component {
            case "", ".":
                continue
            case "..":
                guard !resolved.isEmpty else { throw ResolutionError.invalidLinkTarget(path.string) }
                resolved.removeLast()
                continue
            default:
                break
            }

            let candidate = "/" + (resolved + [component]).joined(separator: "/")
            // destinationOfSymbolicLink throws for anything that is not a link
            // (including paths that do not exist), which is exactly "keep literally".
            guard let destination = try? fileManager.destinationOfSymbolicLink(atPath: candidate) else {
                resolved.append(component)
                guard resolved.count <= SandboxPath.maxComponents else {
                    throw ResolutionError.invalidLinkTarget(path.string)
                }
                continue
            }
            hops = hops.saturatingAdd(1)
            guard hops <= maxHops else { throw ResolutionError.tooManyLinks(path.string) }
            guard destination.utf8.count <= SandboxPath.maxLength, !destination.utf8.contains(0) else {
                throw ResolutionError.invalidLinkTarget(candidate)
            }

            let target = destination.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
            guard target.count + pending.count <= SandboxPath.maxComponents * 2 else {
                throw ResolutionError.invalidLinkTarget(candidate)
            }
            // Absolute target: restart from "/". Relative target: resolve against the
            // link's parent, which is `resolved` as it stands (the link itself was
            // never appended).
            if destination.hasPrefix("/") { resolved = [] }
            pending = (target + Array(pending))[...]
        }
        return SandboxPath(normalisedComponents: resolved)
    }
}
