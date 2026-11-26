import Foundation

/// Why a host rule could not be built.
public enum HostRuleError: Error, Equatable, Sendable {
    case invalidHost(String)
    case invalidPort(Int)
    case domainRuleOnIPLiteral(String)
    /// A subdomain rule on a single-label name (`com`, `localhost`) would grant
    /// every host under it.
    case domainRuleTooBroad(String)
}

/// One allowed network destination. HTTPS only, by design: the manifest has no
/// scheme field, so there is no way to grant plain HTTP by accident.
public struct HostRule: Hashable, Sendable, Comparable, CustomStringConvertible {
    public enum Match: String, Hashable, Sendable {
        /// Exactly this host.
        case exact
        /// This host and any subdomain of it, matched on a label boundary
        /// (`cdn.example.com` covers `img.cdn.example.com`, not `evilcdn.example.com`).
        case includingSubdomains
    }

    public let host: String
    public let port: Int
    public let match: Match

    public static func exact(_ host: String, port: Int = 443) throws -> HostRule {
        try HostRule(host: host, port: port, match: .exact)
    }

    public static func includingSubdomains(of host: String, port: Int = 443) throws -> HostRule {
        let rule = try HostRule(host: host, port: port, match: .includingSubdomains)
        guard !HostClassifier.isIPLiteral(rule.host) else { throw HostRuleError.domainRuleOnIPLiteral(rule.host) }
        // Single-label names are refused. Multi-label public suffixes (`github.io`,
        // `co.uk`) are not detected: no public-suffix list ships here. See README limits.
        guard rule.host.contains(".") else { throw HostRuleError.domainRuleTooBroad(rule.host) }
        return rule
    }

    private init(host: String, port: Int, match: Match) throws {
        guard let normalised = HostClassifier.normalise(host) else {
            throw HostRuleError.invalidHost(host.clamped(to: 80))
        }
        guard (1...65_535).contains(port) else { throw HostRuleError.invalidPort(port) }
        self.host = normalised
        self.port = port
        self.match = match
    }

    func covers(host candidate: String) -> Bool {
        switch match {
        case .exact:
            return candidate == host
        case .includingSubdomains:
            guard !HostClassifier.isIPLiteral(candidate) else { return false }
            return candidate == host || candidate.hasSuffix("." + host)
        }
    }

    public var description: String {
        let scope = match == .exact ? "" : " (and subdomains)"
        return "https://\(host):\(port)\(scope)"
    }

    public static func < (lhs: HostRule, rhs: HostRule) -> Bool {
        (lhs.host, lhs.port, lhs.match.rawValue) < (rhs.host, rhs.port, rhs.match.rawValue)
    }
}

/// Address-class reasoning for hosts. Used to give a precise denial reason and to
/// keep subdomain rules from ever matching an IP literal.
enum HostClassifier {
    enum LocalClass: String, Sendable {
        case loopback, privateNetwork, linkLocal, unspecified, multicastDNS
    }

    /// Lowercases, strips one trailing dot and IPv6 brackets, and rejects anything
    /// that is not plain ASCII host syntax. Non-ASCII hosts must arrive as punycode,
    /// which keeps homoglyph hosts from ever matching an ASCII rule by accident.
    static func normalise(_ raw: String) -> String? {
        var host = raw.lowercased()
        if host.hasPrefix("["), host.hasSuffix("]"), host.count >= 2 {
            host = String(host.dropFirst().dropLast())
        }
        if host.hasSuffix(".") { host.removeLast() }
        guard !host.isEmpty, host.utf8.count <= 253 else { return nil }
        let allowed = Set("abcdefghijklmnopqrstuvwxyz0123456789.-:")
        guard host.allSatisfy({ allowed.contains($0) }) else { return nil }
        if host.contains(":") { return host } // IPv6 literal; dot rules below don't apply
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.allSatisfy({ !$0.isEmpty && $0.count <= 63 }) else { return nil }
        return host
    }

    /// IPv6 (contains ':'), dotted IPv4, and the integer / hex IPv4 spellings that
    /// many resolvers accept (`2130706433`, `0x7f.1`) all count as IP literals:
    /// a host whose final label is numeric or hex-prefixed is never a DNS name.
    static func isIPLiteral(_ host: String) -> Bool {
        if host.contains(":") { return true }
        guard let last = host.split(separator: ".").last else { return false }
        if last.hasPrefix("0x") { return true }
        return last.allSatisfy(\.isASCIIDigit)
    }

    static func localClass(of host: String) -> LocalClass? {
        if host == "localhost" || host.hasSuffix(".localhost") { return .loopback }
        if host.hasSuffix(".local") { return .multicastDNS }
        if host.contains(":") {
            if host == "::1" { return .loopback }
            if host == "::" { return .unspecified }
            if host.hasPrefix("fe8") || host.hasPrefix("fe9") || host.hasPrefix("fea") || host.hasPrefix("feb") {
                return .linkLocal
            }
            if host.hasPrefix("fc") || host.hasPrefix("fd") { return .privateNetwork }
            return nil
        }
        let octets = host.split(separator: ".").map { UInt8($0) }
        guard octets.count == 4, let a = octets[0], let b = octets[1], octets[2] != nil, octets[3] != nil else {
            return nil
        }
        switch (a, b) {
        case (127, _): return .loopback
        case (10, _): return .privateNetwork
        case (172, 16...31): return .privateNetwork
        case (192, 168): return .privateNetwork
        case (169, 254): return .linkLocal
        case (0, _): return .unspecified
        default: return nil
        }
    }
}

private extension Character {
    var isASCIIDigit: Bool { ("0"..."9").contains(self) }
}
