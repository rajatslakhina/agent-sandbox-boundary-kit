/// Why a raw string could not become a `SandboxPath`.
public enum PathError: Error, Equatable, Sendable {
    case notAbsolute(String)
    case containsNUL
    case traversesAboveRoot(String)
    case tooLong
    case tooManyComponents
}

/// An absolute, lexically normalised path: no `.`, no `..`, no empty components.
///
/// Containment is decided component by component, never by string prefix, so
/// `/Workspace-backup` is not inside `/Workspace`.
///
/// A `..` that would climb above `/` is rejected rather than clamped to `/` the
/// way POSIX does: an agent that writes `/../../etc` is probing, and the gate
/// should say so instead of quietly reinterpreting the request.
public struct SandboxPath: Hashable, Sendable, CustomStringConvertible {
    public static let maxLength = 4096
    public static let maxComponents = 256

    public let components: [String]

    public init(_ raw: String) throws {
        guard raw.utf8.count <= Self.maxLength else { throw PathError.tooLong }
        guard !raw.utf8.contains(0) else { throw PathError.containsNUL }
        guard raw.hasPrefix("/") else { throw PathError.notAbsolute(raw.clamped(to: 80)) }

        var normalised: [String] = []
        for part in raw.split(separator: "/", omittingEmptySubsequences: true) {
            switch part {
            case ".":
                continue
            case "..":
                guard !normalised.isEmpty else { throw PathError.traversesAboveRoot(raw.clamped(to: 80)) }
                normalised.removeLast()
            default:
                normalised.append(String(part))
                guard normalised.count <= Self.maxComponents else { throw PathError.tooManyComponents }
            }
        }
        components = normalised
    }

    /// Trusted construction from components that are already normalised.
    init(normalisedComponents: [String]) {
        components = normalisedComponents
    }

    public var string: String { "/" + components.joined(separator: "/") }
    public var description: String { string }
    public var lastComponent: String? { components.last }

    /// True when `self` is `root` or lies beneath it, compared component by component.
    public func isWithin(_ root: SandboxPath) -> Bool {
        guard components.count >= root.components.count else { return false }
        return zip(root.components, components).allSatisfy { $0 == $1 }
    }
}
