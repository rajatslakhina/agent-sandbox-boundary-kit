import XCTest
@testable import AgentSandbox

final class ManifestDigestTests: XCTestCase {
    private func base() throws -> CapabilityManifest {
        CapabilityManifest(
            fileGrants: [try FileGrant("/W", .readWrite), try FileGrant("/R", .readOnly)],
            hosts: [try .exact("api.example.com"), try .includingSubdomains(of: "cdn.example.com")],
            keychainServices: ["k1"],
            appGroups: ["g1"],
            reviewSuffixes: [".env"]
        )
    }

    func testDigestsMatchIndependentlyComputedLiterals() throws {
        // Pinned so a change to the canonical encoding is a visible, reviewed diff:
        // a digest that silently changed would make old audit trails unverifiable.
        XCTAssertEqual(CapabilityManifest().digest, Self.emptyManifestDigest)
        XCTAssertEqual(try base().digest, Self.baseManifestDigest)
    }

    /// FNV-1a 64 of the v1 canonical encoding of an empty manifest, computed by an
    /// independent Python implementation of the same encoding (not by this code).
    static let emptyManifestDigest = "395632dca3b560e9"
    /// Same independent computation, for `base()`.
    static let baseManifestDigest = "6c1aa73acacba2d2"

    /// Six of everything, so an unsorted encoding would almost never iterate two
    /// differently built sets in the same order. Literal from the independent
    /// Python implementation.
    static let wideManifestDigest = "eb9f0df88eb4ed92"

    private func wide(reversed: Bool, capacity: Int) throws -> CapabilityManifest {
        var m = CapabilityManifest()
        m.fileGrants = Set(minimumCapacity: capacity)
        m.hosts = Set(minimumCapacity: capacity)
        m.keychainServices = Set(minimumCapacity: capacity)
        m.appGroups = Set(minimumCapacity: capacity)
        m.reviewSuffixes = Set(minimumCapacity: capacity)
        var indices = Array(0..<6)
        if reversed { indices.reverse() }
        let letters = ["A", "B", "C", "D", "E", "F"]
        for i in indices {
            m.fileGrants.insert(try FileGrant("/" + letters[i], i % 2 == 0 ? .readWrite : .readOnly))
            m.hosts.insert(try .exact("h\(i + 1).example.com"))
            m.keychainServices.insert("k\(i + 1)")
            m.appGroups.insert("g\(i + 1)")
            m.reviewSuffixes.insert(".r\(i + 1)")
        }
        return m
    }

    func testDigestIsSortedSoEveryConstructionHistoryAgrees() throws {
        for (reversed, capacity) in [(false, 0), (true, 0), (false, 64), (true, 257), (false, 1024)] {
            XCTAssertEqual(try wide(reversed: reversed, capacity: capacity).digest, Self.wideManifestDigest)
        }
    }

    func testDigestIgnoresInsertionOrder() throws {
        var a = try base()
        var b = CapabilityManifest()
        b.reviewSuffixes = [".env"]
        b.appGroups = ["g1"]
        b.keychainServices = ["k1"]
        b.hosts = [try .includingSubdomains(of: "cdn.example.com"), try .exact("api.example.com")]
        b.fileGrants = [try FileGrant("/R", .readOnly), try FileGrant("/W", .readWrite)]
        XCTAssertEqual(a.digest, b.digest)
        a.fileGrants.insert(try FileGrant("/W", .readWrite)) // re-inserting is a no-op
        XCTAssertEqual(a.digest, b.digest)
    }

    func testEveryFieldChangesTheDigest() throws {
        let original = try base().digest
        var variants: [CapabilityManifest] = []
        var m = try base(); m.fileGrants = [try FileGrant("/W", .readOnly), try FileGrant("/R", .readOnly)]; variants.append(m)
        m = try base(); m.fileGrants.insert(try FileGrant("/X", .readOnly)); variants.append(m)
        m = try base(); m.hosts = [try .exact("api.example.com", port: 8443), try .includingSubdomains(of: "cdn.example.com")]; variants.append(m)
        m = try base(); m.hosts = [try .includingSubdomains(of: "api.example.com"), try .includingSubdomains(of: "cdn.example.com")]; variants.append(m)
        m = try base(); m.keychainServices = []; variants.append(m)
        m = try base(); m.appGroups = ["g2"]; variants.append(m)
        m = try base(); m.reviewSuffixes = [".token"]; variants.append(m)
        // Moving a value between fields must not collide (fields are tagged).
        m = try base(); m.keychainServices = []; m.appGroups = ["g1", "k1"]; variants.append(m)
        let digests = variants.map(\.digest)
        XCTAssertFalse(digests.contains(original))
        XCTAssertEqual(Set(digests).count, digests.count, "every variant must have its own digest")
    }
}

final class PromptRendererTests: XCTestCase {
    private let tools = [ToolSummary(name: "read_file", summary: "Read a file.")]

    func testPromptStatesEveryGrantDigestReportToolAndLockout() throws {
        let manifest = TemptationCorpus.manifest
        let prompt = SandboxPromptRenderer.render(manifest: manifest, tools: tools, lockout: LockoutPolicy(maxDenials: 3))
        XCTAssertTrue(prompt.contains(manifest.digest))
        XCTAssertTrue(prompt.contains("/AppContainer/Documents/Workspace (read and write)"))
        XCTAssertTrue(prompt.contains("/AppContainer/Documents/Reference (read only)"))
        XCTAssertTrue(prompt.contains("https://api.example.com:443"))
        XCTAssertTrue(prompt.contains("https://cdn.example.com:443 (and subdomains)"))
        XCTAssertTrue(prompt.contains("No Keychain items are available to you."))
        XCTAssertTrue(prompt.contains(".env, .token"))
        XCTAssertTrue(prompt.contains("\(ToolRuntime.reportToolName)(needed:, reason:)"))
        XCTAssertTrue(prompt.contains("After 3 denied calls this session locks"))
        XCTAssertTrue(prompt.contains("- read_file: Read a file."))
    }

    func testPromptListsGrantsAndHostsInSortedOrder() throws {
        var m = CapabilityManifest(fileGrants: Set(minimumCapacity: 300), hosts: Set(minimumCapacity: 300))
        for letter in ["F", "C", "A", "E", "B", "D"] {
            m.fileGrants.insert(try FileGrant("/" + letter, .readOnly))
            m.hosts.insert(try .exact(letter.lowercased() + ".example.com"))
        }
        let prompt = SandboxPromptRenderer.render(manifest: m, tools: [], lockout: .disabled)
        let grantOffsets = ["A", "B", "C", "D", "E", "F"].compactMap { prompt.range(of: "   - /\($0) (read only)")?.lowerBound }
        let hostOffsets = ["a", "b", "c", "d", "e", "f"].compactMap { prompt.range(of: "https://\($0).example.com:443")?.lowerBound }
        XCTAssertEqual(grantOffsets.count, 6)
        XCTAssertEqual(hostOffsets.count, 6)
        XCTAssertEqual(grantOffsets, grantOffsets.sorted())
        XCTAssertEqual(hostOffsets, hostOffsets.sorted())
    }

    func testPromptIsDeterministicAndTracksTheManifest() throws {
        let a = SandboxPromptRenderer.render(manifest: TemptationCorpus.manifest, tools: tools, lockout: .disabled)
        let b = SandboxPromptRenderer.render(manifest: TemptationCorpus.manifest, tools: tools, lockout: .disabled)
        XCTAssertEqual(a, b)
        XCTAssertFalse(a.contains("session locks"))
        var narrowed = TemptationCorpus.manifest
        narrowed.hosts = []
        let c = SandboxPromptRenderer.render(manifest: narrowed, tools: tools, lockout: .disabled)
        XCTAssertNotEqual(a, c)
        XCTAssertFalse(c.contains("api.example.com"))
    }

    func testPromptListsGrantedKeychainAndAppGroupsWhenPresent() throws {
        let m = CapabilityManifest(keychainServices: ["com.example.k"], appGroups: ["group.g"])
        let prompt = SandboxPromptRenderer.render(manifest: m, tools: [], lockout: LockoutPolicy(maxDenials: 1))
        XCTAssertTrue(prompt.contains("Only these Keychain services: com.example.k."))
        XCTAssertTrue(prompt.contains("except these app groups: group.g"))
        XCTAssertTrue(prompt.contains("After 1 denied call this session locks"))
    }
}

final class SupportTests: XCTestCase {
    func testSaturatingAddClampsInsteadOfTrapping() {
        XCTAssertEqual(Int.max.saturatingAdd(1), .max)
        XCTAssertEqual(Int.min.saturatingAdd(-1), .min)
        XCTAssertEqual(2.saturatingAdd(3), 5)
    }

    func testBoundedLogKeepsNewestAndCountsDrops() {
        var log = BoundedLog<Int>(capacity: 3)
        for i in 1...7 { log.append(i) }
        XCTAssertEqual(log.elements, [5, 6, 7])
        XCTAssertEqual(log.dropped, 4)
        var tiny = BoundedLog<Int>(capacity: 0) // clamped to 1
        tiny.append(1); tiny.append(2)
        XCTAssertEqual(tiny.elements, [2])
        XCTAssertEqual(tiny.dropped, 1)
    }

    func testClampedHandlesNonPositiveLimits() {
        XCTAssertEqual("abc".clamped(to: 0), "")
        XCTAssertEqual("abc".clamped(to: -5), "")
        XCTAssertEqual("abc".clamped(to: 2), "ab")
    }
}
