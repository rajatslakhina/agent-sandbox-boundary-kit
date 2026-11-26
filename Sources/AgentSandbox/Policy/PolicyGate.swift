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
        var reviews: [String] = []
        for resource in resources {
            switch evaluate(resource, under: manifest, resolver: resolver) {
            case .allow: continue
            case let .deny(reason): return .deny(reason)
            case let .needsReview(why): reviews.append(why)
            }
        }
        return reviews.isEmpty ? .allow : .needsReview(reviews.joined(separator: "; "))
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
        let containing = manifest.fileGrants.filter { lexical.isWithin($0.root) }
        guard !containing.isEmpty else { return .deny(.outsideFileGrants(lexical.string)) }
        let permitting = access == .write ? containing.filter { $0.mode == .readWrite } : containing
        guard !permitting.isEmpty else { return .deny(.writeNotGranted(lexical.string)) }

        let physical: SandboxPath
        do { physical = try resolver.resolve(lexical) } catch {
            return .deny(.resolutionFailed(lexical.string))
        }
        // The physical path must sit inside the physical root of a grant that also
        // contains the lexical path and permits this access. A root that cannot be
        // resolved grants nothing (fail closed).
        let stillInside = permitting.contains { grant in
            guard let physicalRoot = try? resolver.resolve(grant.root) else { return false }
            return physical.isWithin(physicalRoot)
        }
        guard stillInside else { return .deny(.symlinkEscape(lexical: lexical.string, resolved: physical.string)) }

        let flagged = manifest.reviewSuffixes.map { $0.lowercased() }.filter { suffix in
            [lexical.lastComponent, physical.lastComponent].contains { name in
                name.map { $0.lowercased().hasSuffix(suffix) } ?? false
            }
        }
        guard flagged.isEmpty else {
            return .needsReview("\(access.rawValue) of \(lexical.string) matches review suffix \(flagged.sorted().joined(separator: ", "))")
        }
        return .allow
    }

    private func evaluateNetwork(_ raw: String, _ manifest: CapabilityManifest) -> RuleOutcome {
        let shown = raw.clamped(to: 120)
        guard let parts = URLComponents(string: raw) else { return .deny(.malformedURL(shown)) }
        let scheme = parts.scheme?.lowercased() ?? ""
        guard scheme == "https" else { return .deny(.schemeNotAllowed(scheme.clamped(to: 20))) }
        guard parts.user == nil, parts.password == nil else { return .deny(.credentialsInURL) }
        guard let rawHost = parts.percentEncodedHost, !rawHost.contains("%"),
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
