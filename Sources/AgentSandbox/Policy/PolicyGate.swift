import Foundation

/// Judges one resource against a manifest. `PolicyGate` is the real implementation;
/// the evaluation harness also runs deliberately weaker ones (see `Baselines.swift`)
/// to show what the corpus catches.
public protocol AccessEvaluating: Sendable {
    var name: String { get }
    func evaluate(_ resource: Resource, under manifest: CapabilityManifest, resolver: any PathResolving) -> RuleOutcome
}

extension AccessEvaluating {
    /// All resources of one call: the first denial wins; otherwise any review flag
    /// sends the call to review; otherwise it is allowed. A call that declares no
    /// resources (pure computation) is allowed.
    func evaluate(_ resources: [Resource], under manifest: CapabilityManifest, resolver: any PathResolving) -> RuleOutcome {
        var reviews: [ReviewFlag] = []
        for resource in resources {
            switch evaluate(resource, under: manifest, resolver: resolver) {
            case .allow: continue
            case let .deny(reason): return .deny(reason)
            case let .needsReview(flags): reviews.append(contentsOf: flags)
            }
        }
        return reviews.isEmpty ? .allow : .needsReview(reviews)
    }
}

/// The deterministic rules. Pure and synchronous: no clock, no I/O except what the
/// injected resolver does, so every verdict is reproducible from (resource, manifest).
public struct PolicyGate: AccessEvaluating {
    public init() {}

    public var name: String { "PolicyGate" }

    public func evaluate(_ resource: Resource, under manifest: CapabilityManifest, resolver: any PathResolving) -> RuleOutcome {
        switch resource {
        case let .file(path, access):
            return evaluateFile(path, access, manifest, resolver)
        case let .network(url):
            return evaluateNetwork(url, manifest)
        case let .keychain(service):
            return manifest.keychainServices.contains(service) ? .allow : .deny(.keychainForbidden(service.clamped(to: 120)))
        case let .appGroup(identifier):
            return manifest.appGroups.contains(identifier) ? .allow : .deny(.appGroupForbidden(identifier.clamped(to: 120)))
        }
    }

    private func evaluateFile(
        _ raw: String, _ access: FileAccess, _ manifest: CapabilityManifest, _ resolver: any PathResolving
    ) -> RuleOutcome {
        let lexical: SandboxPath
        do { lexical = try SandboxPath(raw) } catch {
            return .deny(.invalidPath(String(describing: error)))
        }
        // The deepest grant that contains a path decides its mode, so a read-only
        // folder nested inside a read-write one stays read-only.
        guard let lexicalMode = Self.decidingMode(for: lexical, among: manifest.fileGrants.map { ($0, $0.root) }) else {
            return .deny(.outsideFileGrants(lexical.string))
        }
        if access == .write, lexicalMode != .readWrite {
            return .deny(.writeNotGranted(lexical.string))
        }

        let physical: SandboxPath
        do { physical = try resolver.resolve(lexical) } catch {
            return .deny(.resolutionFailed(lexical.string))
        }
        // The physical path is judged the same way against the physical roots. A
        // root that cannot be resolved grants nothing (fail closed).
        let physicalRoots = manifest.fileGrants.compactMap { grant in
            (try? resolver.resolve(grant.root)).map { (grant, $0) }
        }
        guard let physicalMode = Self.decidingMode(for: physical, among: physicalRoots),
              access == .read || physicalMode == .readWrite
        else {
            return .deny(.symlinkEscape(lexical: lexical.string, resolved: physical.string))
        }

        let flagged = manifest.reviewSuffixes.map { $0.lowercased() }.filter { suffix in
            [lexical.lastComponent, physical.lastComponent].contains { name in
                name.map { $0.lowercased().hasSuffix(suffix) } ?? false
            }
        }
        guard flagged.isEmpty else {
            // The resolved path is part of the flag, so the post-review re-check
            // notices a link repointed to a different file while the call was parked.
            return .needsReview([ReviewFlag(access: access, lexical: lexical, physical: physical, suffixes: flagged.sorted())])
        }
        return .allow
    }

    /// The mode of the grant whose root is the longest prefix of `path`, or `nil`
    /// when no grant contains it. On a tie (the same root listed twice with
    /// different modes) the more restrictive mode wins.
    ///
    /// Containment is exact (case-sensitive), so a case variant never makes a path
    /// "inside" on a case-sensitive volume. But on a case-insensitive volume
    /// (default macOS APFS, and so the iOS Simulator) `/W/reference` IS
    /// `/W/Reference`; so a read-only grant at least as deep that matches ignoring
    /// case also forces read-only. That rule can only narrow (fail closed).
    static func decidingMode(for path: SandboxPath, among grants: [(FileGrant, SandboxPath)]) -> FileGrant.Mode? {
        var best: (mode: FileGrant.Mode, depth: Int)?
        for (grant, root) in grants where path.isWithin(root) {
            let depth = root.components.count
            if let current = best {
                if depth > current.depth || (depth == current.depth && grant.mode == .readOnly) {
                    best = (grant.mode, depth)
                }
            } else {
                best = (grant.mode, depth)
            }
        }
        guard let decided = best else { return nil }
        if decided.mode == .readWrite {
            let caseVariantReadOnly = grants.contains { grant, root in
                grant.mode == .readOnly && root.components.count >= decided.depth && path.isWithinIgnoringCase(root)
            }
            if caseVariantReadOnly { return .readOnly }
        }
        return decided.mode
    }

    private func evaluateNetwork(_ raw: String, _ manifest: CapabilityManifest) -> RuleOutcome {
        let shown = raw.clamped(to: 120)
        guard let parts = URLComponents(string: raw) else { return .deny(.malformedURL(shown)) }
        let scheme = parts.scheme?.lowercased() ?? ""
        guard scheme == "https" else { return .deny(.schemeNotAllowed(scheme.clamped(to: 20))) }
        guard parts.user == nil, parts.password == nil else { return .deny(.credentialsInURL) }
        // `normalise` admits only [a-z0-9.-:], so a percent-encoded host is rejected there.
        guard let rawHost = parts.percentEncodedHost,
              let host = HostClassifier.normalise(rawHost)
        else { return .deny(.malformedURL(shown)) }
        let port = parts.port ?? 443
        guard (1...65_535).contains(port) else { return .deny(.malformedURL(shown)) }

        let hostMatches = manifest.hosts.filter { $0.covers(host: host) }
        if hostMatches.contains(where: { $0.port == port }) { return .allow }
        if !hostMatches.isEmpty { return .deny(.portNotAllowed(host: host, port: port)) }
        if let local = HostClassifier.localClass(of: host) {
            return .deny(.localNetwork(host: host, kind: local.rawValue))
        }
        if HostClassifier.isIPLiteral(host) { return .deny(.ipLiteralNotAllowed(host)) }
        return .deny(.hostNotAllowed(host))
    }
}
