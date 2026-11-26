import Foundation

/// No gate at all: every resource is allowed. The "without mitigation" baseline
/// for the evaluation harness. Never ship this.
public struct UnguardedEvaluator: AccessEvaluating {
    public init() {}
    public var name: String { "No gate" }
    public func evaluate(_ resource: Resource, under manifest: CapabilityManifest, resolver: any PathResolving) -> RuleOutcome {
        .allow
    }
}

/// The gate people write first, and deliberately broken in the ways that matter:
/// string-prefix path containment on the raw (unnormalised, unresolved) path, and
/// suffix host matching without a label boundary, scheme or port check. Keychain
/// and app-group checks are correct, so every difference from `PolicyGate` in an
/// eval report comes from parsing, not from a missing category.
///
/// It exists so the evaluation harness can prove its corpus catches these bugs.
/// Never ship this.
public struct NaivePrefixEvaluator: AccessEvaluating {
    public init() {}
    public var name: String { "Naive string-prefix gate" }

    public func evaluate(_ resource: Resource, under manifest: CapabilityManifest, resolver: any PathResolving) -> RuleOutcome {
        switch resource {
        case let .file(path, access):
            let inside = manifest.fileGrants.filter { path.hasPrefix($0.root.string) }
            guard !inside.isEmpty else { return .deny(.outsideFileGrants(path)) }
            if access == .write, !inside.contains(where: { $0.mode == .readWrite }) {
                return .deny(.writeNotGranted(path))
            }
            return .allow
        case let .network(url):
            guard let host = URL(string: url)?.host?.lowercased() else { return .deny(.malformedURL(url)) }
            return manifest.hosts.contains { host.hasSuffix($0.host) } ? .allow : .deny(.hostNotAllowed(host))
        case let .keychain(service):
            return manifest.keychainServices.contains(service) ? .allow : .deny(.keychainForbidden(service))
        case let .appGroup(identifier):
            return manifest.appGroups.contains(identifier) ? .allow : .deny(.appGroupForbidden(identifier))
        }
    }
}
