/// A directory the agent may use, and how.
public struct FileGrant: Hashable, Sendable, Comparable {
    public enum Mode: String, Hashable, Sendable {
        case readOnly
        case readWrite
    }

    public let root: SandboxPath
    public let mode: Mode

    public init(root: SandboxPath, mode: Mode) {
        self.root = root
        self.mode = mode
    }

    public init(_ root: String, _ mode: Mode) throws {
        self.init(root: try SandboxPath(root), mode: mode)
    }

    public static func < (lhs: FileGrant, rhs: FileGrant) -> Bool {
        (lhs.root.string, lhs.mode.rawValue) < (rhs.root.string, rhs.mode.rawValue)
    }
}

/// The single source of truth for what the agent may touch. The same value is
/// rendered into the system prompt (`SandboxPromptRenderer`) and enforced by the
/// gate (`PolicyGate`), and both carry its `digest`, so you can prove from the
/// audit trail that the rules the model was shown are the rules that judged it.
///
/// Everything not granted is denied. There is no "allow all" switch.
public struct CapabilityManifest: Hashable, Sendable {
    public var fileGrants: Set<FileGrant>
    public var hosts: Set<HostRule>
    public var keychainServices: Set<String>
    public var appGroups: Set<String>
    /// File-name suffixes (case-insensitive) that need a second look even inside a
    /// granted root, such as ".token" or ".env". Matching calls go to the classifier.
    public var reviewSuffixes: Set<String>

    public init(
        fileGrants: Set<FileGrant> = [],
        hosts: Set<HostRule> = [],
        keychainServices: Set<String> = [],
        appGroups: Set<String> = [],
        reviewSuffixes: Set<String> = []
    ) {
        self.fileGrants = fileGrants
        self.hosts = hosts
        self.keychainServices = keychainServices
        self.appGroups = appGroups
        self.reviewSuffixes = reviewSuffixes
    }

    /// Order-independent: built from sorted, tagged, length-prefixed fields, so
    /// manifests built from byte-identical values have equal digests regardless of
    /// construction order. (Swift `==` on the sets uses canonical equivalence, so an
    /// NFC and an NFD spelling compare equal but digest differently; the gate, like
    /// the digest, treats Keychain and app-group names as bytes.)
    public var digest: String {
        var hasher = FNV1a64()
        hasher.combine("agent-sandbox-manifest/v1")
        hasher.combine("files")
        let grants = fileGrants.sorted()
        hasher.combine(count: grants.count)
        for grant in grants {
            hasher.combine(grant.root.string)
            hasher.combine(grant.mode.rawValue)
        }
        hasher.combine("hosts")
        let rules = hosts.sorted()
        hasher.combine(count: rules.count)
        for rule in rules {
            hasher.combine(rule.host)
            hasher.combine(count: rule.port)
            hasher.combine(rule.match.rawValue)
        }
        for (tag, values) in [("keychain", keychainServices), ("appGroups", appGroups), ("review", reviewSuffixes)] {
            hasher.combine(tag)
            let sorted = values.sorted()
            hasher.combine(count: sorted.count)
            for value in sorted { hasher.combine(value) }
        }
        return hasher.hex
    }
}
