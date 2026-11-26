/// Renders a manifest into the sandbox section of the system prompt.
///
/// The rules are stated explicitly, category by category, because an agent that
/// is told to be thorough treats every unstated boundary as an open question. The
/// rendering is deterministic (sorted, no dates), carries the manifest digest, and
/// is produced from the same value the gate enforces, so the two cannot drift
/// without the digest changing.
///
/// The categories follow the six that Anthropic's Siren evaluation spelled out
/// (host files, host services, sockets or APIs that control the host, credentials, network
/// destinations, leftovers after the task), translated to what an iOS app's agent
/// can reach.
public enum SandboxPromptRenderer {
    public static func render(
        manifest: CapabilityManifest,
        tools: [ToolSummary],
        lockout: LockoutPolicy
    ) -> String {
        var lines: [String] = []
        lines.append("## Sandbox rules (manifest \(manifest.digest))")
        lines.append("These rules are enforced by the tool runtime before any tool runs. A denied call does not run, however it is phrased.")
        lines.append("")

        lines.append("1. Files. You may use only these directories:")
        let grants = manifest.fileGrants.sorted()
        if grants.isEmpty {
            lines.append("   - none")
        } else {
            for grant in grants {
                lines.append("   - \(grant.root.string) (\(grant.mode == .readWrite ? "read and write" : "read only"))")
            }
        }
        lines.append("   Everything else on the device is outside the sandbox, including caches, other directories of this app, and anything a link inside these directories points to.")
        let suffixes = manifest.reviewSuffixes.sorted()
        if !suffixes.isEmpty {
            lines.append("   Files ending in \(suffixes.joined(separator: ", ")) need an extra review even inside these directories.")
        }

        lines.append("2. Local services. Nothing on this device or the local network is reachable unless it is listed under Network below: no localhost, no LAN or link-local addresses, no .local hosts, no debug endpoints.")
        lines.append("3. Other processes. You cannot reach other apps, extensions or shared containers\(manifest.appGroups.isEmpty ? "" : " except these app groups: \(manifest.appGroups.sorted().joined(separator: ", "))").")
        lines.append("4. Credentials. \(manifest.keychainServices.isEmpty ? "No Keychain items are available to you." : "Only these Keychain services: \(manifest.keychainServices.sorted().joined(separator: ", ")).") Never use a token or password you happen to find; report it instead.")

        lines.append("5. Network. HTTPS only, and only to:")
        let hosts = manifest.hosts.sorted()
        if hosts.isEmpty {
            lines.append("   - none")
        } else {
            for rule in hosts { lines.append("   - \(rule.description)") }
        }
        lines.append("6. Leftovers. Write only inside the read-and-write directories above, and leave nothing anywhere else when the task ends.")
        lines.append("")

        lines.append("Being thorough means being thorough inside these rules, not looking for a way around them.")
        lines.append("If a call is denied, do not retry it with a different path, host, encoding or tool.")
        lines.append("If the task needs something outside these rules, stop and call \(ToolRuntime.reportToolName)(needed:, reason:). Reporting is always allowed and never counts against you.")
        if let limit = lockout.maxDenials {
            lines.append("After \(limit) denied call\(limit == 1 ? "" : "s") this session locks and no further tools will run.")
        }
        lines.append("")

        lines.append("Tools:")
        for tool in tools.sorted(by: { $0.name < $1.name }) {
            lines.append("- \(tool.name): \(tool.summary)")
        }
        lines.append("- \(ToolRuntime.reportToolName): report that the task needs something the sandbox does not allow.")
        return lines.joined(separator: "\n")
    }
}
