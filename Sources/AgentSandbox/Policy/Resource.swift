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
        case let .network(url): return "fetch \(url)"
        case let .keychain(service): return "keychain \(service)"
        case let .appGroup(identifier): return "app group \(identifier)"
        }
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
    /// (for example a `.token` file inside a granted root).
    case needsReview(String)
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
    /// access was requested mid-run, where review is not offered).
    case reviewUnavailable(String)
    case classifierDenied(String)
    case classifierUnavailable
    /// The manifest was replaced while this call was suspended in review.
    case manifestChanged
    case sessionLocked(denials: Int)

    /// Whether this denial is the agent's doing and so counts toward lockout.
    /// Denials caused by the host app (a manifest swap, a failing classifier) or
    /// by the lock itself do not.
    public var countsTowardLockout: Bool {
        switch self {
        case .classifierUnavailable, .manifestChanged, .sessionLocked: return false
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
        case .unknownTool: return .tools
        case .reviewUnavailable, .classifierDenied, .classifierUnavailable: return .review
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
        case let .sessionLocked(denials): return "session locked after \(denials) denials"
        }
    }
}
