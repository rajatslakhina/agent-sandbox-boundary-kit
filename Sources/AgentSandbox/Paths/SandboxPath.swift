import Foundation

/// Why a raw string could not become a `SandboxPath`.
public enum PathError: Error, Equatable, Sendable {
    case notAbsolute(String)
    case containsNUL
    /// The path contains a `..` component. See `SandboxPath` for why these are
    /// rejected rather than collapsed.
    case parentReference(String)
    case tooLong
    case tooManyComponents
}

/// An absolute path with no `.`, no `..` and no empty components.
///
/// **`..` is rejected, not collapsed.** Collapsing `a/link/../b` to `a/b` as text
/// is only correct when nothing on the way is a symlink: the kernel applies `..`
/// *after* following `link`, so `Workspace/cache-link/../Preferences` opens a
/// directory next to wherever `cache-link` points, not next to `cache-link`. A
/// gate that collapses first and resolves second can be walked straight out of.
/// An agent never needs `..` to name a file inside its grants, so the safe rule
/// is also the simple one. (`.` and repeated slashes are harmless and are dropped.)
///
/// Containment is decided component by component, never by string prefix, so
/// `/Workspace-backup` is not inside `/Workspace`.
public struct SandboxPath: Hashable, Sendable, CustomStringConvertible {
    public static let maxLength = 4096
    public static let maxComponents = 256

    public let components: [String]

    public init(_ raw: String) throws {
        guard raw.utf8.count <= Self.maxLength else { throw PathError.tooLong }
        guard !raw.utf8.contains(0) else { throw PathError.containsNUL }
        guard raw.hasPrefix("/") else { throw PathError.notAbsolute(raw.clamped(to: 80)) }

        var parts: [String] = []
        for part in raw.split(separator: "/", omittingEmptySubsequences: true) {
            switch part {
            case ".":
                continue
            case "..":
                throw PathError.parentReference(raw.clamped(to: 80))
            default:
                parts.append(String(part))
                guard parts.count <= Self.maxComponents else { throw PathError.tooManyComponents }
            }
        }
        components = parts
    }

    /// Trusted construction from components that already satisfy the invariants.
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

    /// Like `isWithin`, ignoring case. Used only to make a decision stricter.
    func isWithinIgnoringCase(_ root: SandboxPath) -> Bool {
        guard components.count >= root.components.count else { return false }
        return zip(root.components, components).allSatisfy { $0.caseInsensitiveCompare($1) == .orderedSame }
    }
}
