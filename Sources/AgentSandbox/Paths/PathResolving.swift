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
        self.maxHops = max(1, maxHops)
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
/// written) are kept literally. Relative link targets resolve against the link's
/// parent directory; `..` in a target that climbs above `/` fails closed.
public struct FileSystemResolver: PathResolving {
    public let maxHops: Int

    public init(maxHops: Int = 40) {
        self.maxHops = max(1, maxHops)
    }

    public func resolve(_ path: SandboxPath) throws -> SandboxPath {
        let fileManager = FileManager.default
        var resolved: [String] = []
        var pending = path.components[...]
        var hops = 0

        while let component = pending.first {
            pending = pending.dropFirst()
            let candidate = "/" + (resolved + [component]).joined(separator: "/")
            // destinationOfSymbolicLink throws for anything that is not a link
            // (including paths that do not exist), which is exactly "keep literally".
            guard let destination = try? fileManager.destinationOfSymbolicLink(atPath: candidate) else {
                resolved.append(component)
                continue
            }
            hops = hops.saturatingAdd(1)
            guard hops <= maxHops else { throw ResolutionError.tooManyLinks(path.string) }

            let base = destination.hasPrefix("/")
                ? destination
                : "/" + resolved.joined(separator: "/") + "/" + destination
            let target: SandboxPath
            do { target = try SandboxPath(base) } catch {
                throw ResolutionError.invalidLinkTarget(candidate)
            }
            guard target.components.count + pending.count <= SandboxPath.maxComponents else {
                throw ResolutionError.invalidLinkTarget(candidate)
            }
            resolved = []
            pending = (target.components + Array(pending))[...]
        }
        return SandboxPath(normalisedComponents: resolved)
    }
}
