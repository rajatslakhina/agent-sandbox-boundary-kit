import Foundation

/// What a tool call wants to touch. Every tool declares these before it runs, and
/// may ask for more at run time through `ToolContext.authorize(_:)`.
public enum Resource: Hashable, Sendable, CustomStringConvertible {
    case file(path: String, access: FileAccess)
    case network(url: String)
    case keychain(service: String)
    case appGroup(identifier: String)

    public var description: String {
        switch self {
        case let .file(path, access): return "\(access.rawValue) \(path)"
        case let .network(url): return "fetch \(Self.redactingUserInfo(url))"
        case let .keychain(service): return "keychain \(service)"
        case let .appGroup(identifier): return "app group \(identifier)"
        }
    }
}

extension Resource {
    /// The URL with any user name and password removed, so credentials typed into
    /// a URL never reach the audit trail or a screen.
    static func redactingUserInfo(_ url: String) -> String {
        if var parts = URLComponents(string: url) {
            guard parts.user != nil || parts.password != nil else { return url }
            parts.user = nil
            parts.password = nil
            return (parts.string ?? "(URL not shown)") + " [user info removed]"
        }
        // Unparseable: cut anything up to the last "@" in the authority by hand, so a
        // malformed URL cannot smuggle its credentials into the log either.
        guard url.contains("@") else { return url }
        guard let schemeEnd = url.range(of: "://") else { return "(unparseable URL containing '@', not shown)" }
        let afterScheme = url[schemeEnd.upperBound...]
        let authorityEnd = afterScheme.firstIndex(where: { "/?#".contains($0) }) ?? afterScheme.endIndex
        let authority = afterScheme[..<authorityEnd]
        guard let at = authority.lastIndex(of: "@") else { return url }
        return String(url[..<schemeEnd.upperBound]) + String(authority[authority.index(after: at)...])
            + String(afterScheme[authorityEnd...]) + " [user info removed]"
    }
}

public enum FileAccess: String, Hashable, Sendable {
    case read
    case write
}

/// The verdict of the deterministic rules for one resource.
public enum RuleOutcome: Equatable, Sendable {
    case allow
    case deny(DenialReason)
    /// The rules allow it but the manifest flags it for a second look
    /// (for example a `.token` file inside a granted root). Carries the full,
    /// unclamped identity of every flagged access, so the runtime can tell after
    /// review whether it is still judging exactly what was reviewed.
    case needsReview([ReviewFlag])
}

/// One flagged access: what was asked for, where it really resolves, and which
/// review suffixes it matched.
public struct ReviewFlag: Hashable, Sendable, CustomStringConvertible {
    public let access: FileAccess
    public let lexical: SandboxPath
    public let physical: SandboxPath
    public let suffixes: [String]

    public init(access: FileAccess, lexical: SandboxPath, physical: SandboxPath, suffixes: [String]) {
        self.access = access
        self.lexical = lexical
        self.physical = physical
        self.suffixes = suffixes
    }

    public var description: String {
        let target = physical == lexical ? "" : " (resolves to \(physical.string.clamped(to: 200)))"
        return "\(access.rawValue) of \(lexical.string.clamped(to: 200))\(target) matches review suffix \(suffixes.joined(separator: ", "))"
    }

    /// A bounded, human-readable summary of many flags (at most three listed).
    public static func summary(_ flags: [ReviewFlag]) -> String {
        let shown = flags.prefix(3).map(\.description).joined(separator: "; ")
        return flags.count > 3 ? "\(shown); and \(flags.count - 3) more" : shown
    }
}

/// Why a call, or one access inside a call, was refused. The full reason goes to
/// the audit trail; the agent only ever sees `agentFacingMessage`, which names a
/// category and nothing else, so denials cannot be used to map the file system.
public enum DenialReason: Hashable, Sendable, CustomStringConvertible {
    case unknownTool(String)
    case invalidPath(String)
    case outsideFileGrants(String)
    case writeNotGranted(String)
    case symlinkEscape(lexical: String, resolved: String)
    case resolutionFailed(String)
    case schemeNotAllowed(String)
    case credentialsInURL
    case malformedURL(String)
    case localNetwork(host: String, kind: String)
    case ipLiteralNotAllowed(String)
    case hostNotAllowed(String)
    case portNotAllowed(host: String, port: Int)
    case keychainForbidden(String)
    case appGroupForbidden(String)
    /// Flagged for review, but no review path exists (no classifier, or the
    /// access was requested mid-run, where review is not offered). The string is
    /// `ReviewFlag.summary` of the flags.
    case reviewUnavailable(String)
    case classifierDenied(String)
    case classifierUnavailable
    /// The manifest was replaced while this call was suspended in review.
    case manifestChanged
    /// The deterministic rules, re-run after review, no longer give the verdict
    /// that was reviewed (for example a symlink changed while the call was parked).
    case verdictChangedDuringReview
    /// A tool called `ToolContext.authorize(_:)` after its call had finished.
    case callNotActive
    case sessionLocked(denials: Int)

    /// The same reason with every string payload clamped, so an audit entry stays
    /// bounded however long the offending input was.
    public func clamped(to limit: Int = 300) -> DenialReason {
        switch self {
        case let .unknownTool(s): return .unknownTool(s.clamped(to: limit))
        case let .invalidPath(s): return .invalidPath(s.clamped(to: limit))
        case let .outsideFileGrants(s): return .outsideFileGrants(s.clamped(to: limit))
        case let .writeNotGranted(s): return .writeNotGranted(s.clamped(to: limit))
        case let .symlinkEscape(l, r): return .symlinkEscape(lexical: l.clamped(to: limit), resolved: r.clamped(to: limit))
        case let .resolutionFailed(s): return .resolutionFailed(s.clamped(to: limit))
        case let .schemeNotAllowed(s): return .schemeNotAllowed(s.clamped(to: limit))
        case let .malformedURL(s): return .malformedURL(s.clamped(to: limit))
        case let .localNetwork(h, k): return .localNetwork(host: h.clamped(to: limit), kind: k)
        case let .ipLiteralNotAllowed(s): return .ipLiteralNotAllowed(s.clamped(to: limit))
        case let .hostNotAllowed(s): return .hostNotAllowed(s.clamped(to: limit))
        case let .portNotAllowed(h, p): return .portNotAllowed(host: h.clamped(to: limit), port: p)
        case let .keychainForbidden(s): return .keychainForbidden(s.clamped(to: limit))
        case let .appGroupForbidden(s): return .appGroupForbidden(s.clamped(to: limit))
        case let .reviewUnavailable(s): return .reviewUnavailable(s.clamped(to: limit))
        case let .classifierDenied(s): return .classifierDenied(s.clamped(to: limit))
        case .credentialsInURL, .classifierUnavailable, .manifestChanged, .verdictChangedDuringReview,
             .callNotActive, .sessionLocked:
            return self
        }
    }

    /// Whether this denial is the agent's doing and so counts toward lockout.
    /// Denials caused by the host app or its tools (a manifest swap, a failing
    /// classifier, a verdict that changed during review, a tool authorizing after
    /// its call ended) or by the lock itself do not. Counted besides the plain
    /// rule denials: a flagged resource with no classifier configured, a flagged
    /// resource requested mid-run (both `reviewUnavailable`: review is offered
    /// only up front, and only if the host configured it), and a classifier denial.
    public var countsTowardLockout: Bool {
        switch self {
        case .classifierUnavailable, .manifestChanged, .verdictChangedDuringReview, .callNotActive, .sessionLocked:
            return false
        default: return true
        }
    }

    public enum Category: String, Sendable {
        case files, network, credentials, sharedContainers, tools, review, session
    }

    public var category: Category {
        switch self {
        case .invalidPath, .outsideFileGrants, .writeNotGranted, .symlinkEscape, .resolutionFailed:
            return .files
        case .schemeNotAllowed, .credentialsInURL, .malformedURL, .localNetwork, .ipLiteralNotAllowed,
             .hostNotAllowed, .portNotAllowed:
            return .network
        case .keychainForbidden: return .credentials
        case .appGroupForbidden: return .sharedContainers
        case .unknownTool, .callNotActive: return .tools
        case .reviewUnavailable, .classifierDenied, .classifierUnavailable, .verdictChangedDuringReview: return .review
        case .manifestChanged, .sessionLocked: return .session
        }
    }

    /// What the runtime tells the model. Deliberately free of paths, hosts and
    /// resolved link targets, and it always points at the report tool.
    public var agentFacingMessage: String {
        "Denied by the sandbox policy (\(category.rawValue)). Do not retry with a different path, host, encoding or tool. "
            + "If the task genuinely needs this, call \(ToolRuntime.reportToolName) and explain what you need."
    }

    public var description: String {
        switch self {
        case let .unknownTool(name): return "unknown tool '\(name)'"
        case let .invalidPath(why): return "invalid path: \(why)"
        case let .outsideFileGrants(path): return "\(path) is outside every file grant"
        case let .writeNotGranted(path): return "\(path) is in a read-only grant"
        case let .symlinkEscape(lexical, resolved): return "\(lexical) resolves outside its grant, to \(resolved)"
        case let .resolutionFailed(path): return "could not resolve \(path)"
        case let .schemeNotAllowed(scheme): return "scheme '\(scheme)' is not allowed (https only)"
        case .credentialsInURL: return "URL carries user info"
        case let .malformedURL(url): return "malformed URL \(url)"
        case let .localNetwork(host, kind): return "\(host) is a local-network address (\(kind))"
        case let .ipLiteralNotAllowed(host): return "IP literal \(host) is not in the allowlist"
        case let .hostNotAllowed(host): return "host \(host) is not in the allowlist"
        case let .portNotAllowed(host, port): return "port \(port) is not allowed for \(host)"
        case let .keychainForbidden(service): return "keychain service \(service) is not granted"
        case let .appGroupForbidden(id): return "app group \(id) is not granted"
        case let .reviewUnavailable(why): return "needs review but none is available: \(why)"
        case let .classifierDenied(why): return "classifier denied: \(why)"
        case .classifierUnavailable: return "classifier failed; failing closed"
        case .manifestChanged: return "manifest changed during review"
        case .verdictChangedDuringReview: return "rules gave a different verdict after review"
        case .callNotActive: return "authorize called after the call finished"
        case let .sessionLocked(denials): return "session locked after \(denials) denials"
        }
    }
}
