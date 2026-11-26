/// What the classifier sees: the call, its declared resources, why the rules
/// flagged it, and the digest of the manifest it is being judged under.
public struct ReviewRequest: Sendable, Equatable {
    public let call: ToolCall
    public let resources: [Resource]
    public let flaggedBecause: String
    public let manifestDigest: String
}

public enum ClassifierDecision: Equatable, Sendable {
    case allow
    case deny(String)
}

/// The second stage of the gate, consulted only for calls the deterministic rules
/// allowed but flagged. It can only narrow: it never sees, and so can never
/// overturn, a deterministic denial. If it throws, the call is denied.
///
/// An on-device Foundation Models classifier is the intended production
/// implementation; this package ships only the protocol and a deterministic
/// stand-in, `ToolTrustClassifier`, so behaviour is testable without a model.
///
/// The runtime does not time the classifier out. A classifier must bound its own
/// latency (and should honour task cancellation); see the README's limits.
public protocol CallClassifier: Sendable {
    func classify(_ request: ReviewRequest) async throws -> ClassifierDecision
}

/// Allows flagged calls only from tools you have explicitly trusted with
/// sensitive files, and denies the rest.
public struct ToolTrustClassifier: CallClassifier {
    public let trustedTools: Set<String>

    public init(trustedTools: Set<String>) {
        self.trustedTools = trustedTools
    }

    public func classify(_ request: ReviewRequest) async throws -> ClassifierDecision {
        trustedTools.contains(request.call.tool)
            ? .allow
            : .deny("tool '\(request.call.tool)' is not trusted with flagged files")
    }
}
