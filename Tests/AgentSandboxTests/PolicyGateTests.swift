import XCTest
@testable import AgentSandbox

final class NetworkRuleTests: XCTestCase {
    private let gate = PolicyGate()
    private let resolver = LexicalResolver()

    private func manifest() throws -> CapabilityManifest {
        CapabilityManifest(hosts: [
            try .exact("api.example.com"),
            try .includingSubdomains(of: "cdn.example.com"),
            try .exact("10.0.0.5", port: 8443),
        ])
    }

    private func verdict(_ url: String) throws -> RuleOutcome {
        gate.evaluate(.network(url: url), under: try manifest(), resolver: resolver)
    }

    func testAllowsExactHostOnItsPortWithCaseAndTrailingDotNormalised() throws {
        XCTAssertEqual(try verdict("https://api.example.com/v1"), .allow)
        XCTAssertEqual(try verdict("https://API.Example.COM./v1"), .allow)
        XCTAssertEqual(try verdict("https://api.example.com:443/v1"), .allow)
    }

    func testDeniesOtherPortsOnAnAllowedHost() throws {
        XCTAssertEqual(try verdict("https://api.example.com:8443/admin"), .deny(.portNotAllowed(host: "api.example.com", port: 8443)))
    }

    func testSubdomainRuleMatchesOnLabelBoundaryOnly() throws {
        XCTAssertEqual(try verdict("https://cdn.example.com/a"), .allow)
        XCTAssertEqual(try verdict("https://img.cdn.example.com/a"), .allow)
        XCTAssertEqual(try verdict("https://evilcdn.example.com/a"), .deny(.hostNotAllowed("evilcdn.example.com")))
        XCTAssertEqual(try verdict("https://api.example.com.attacker.net/a"), .deny(.hostNotAllowed("api.example.com.attacker.net")))
        // `exact` does not cover subdomains.
        XCTAssertEqual(try verdict("https://v2.api.example.com/a"), .deny(.hostNotAllowed("v2.api.example.com")))
    }

    func testDeniesPlainHTTPAndUserInfo() throws {
        XCTAssertEqual(try verdict("http://api.example.com/v1"), .deny(.schemeNotAllowed("http")))
        XCTAssertEqual(try verdict("https://api.example.com@192.168.1.20/debug"), .deny(.credentialsInURL))
        XCTAssertEqual(try verdict("https://u:p@api.example.com/"), .deny(.credentialsInURL))
    }

    func testClassifiesLocalAddressesAndIPLiterals() throws {
        XCTAssertEqual(try verdict("https://192.168.1.20:8080/x"), .deny(.localNetwork(host: "192.168.1.20", kind: "privateNetwork")))
        XCTAssertEqual(try verdict("https://127.0.0.1/x"), .deny(.localNetwork(host: "127.0.0.1", kind: "loopback")))
        XCTAssertEqual(try verdict("https://localhost:8080/x"), .deny(.localNetwork(host: "localhost", kind: "loopback")))
        XCTAssertEqual(try verdict("https://printer.local/x"), .deny(.localNetwork(host: "printer.local", kind: "multicastDNS")))
        XCTAssertEqual(try verdict("https://169.254.1.1/x"), .deny(.localNetwork(host: "169.254.1.1", kind: "linkLocal")))
        XCTAssertEqual(try verdict("https://[::1]/x"), .deny(.localNetwork(host: "::1", kind: "loopback")))
        XCTAssertEqual(try verdict("https://2130706433/x"), .deny(.ipLiteralNotAllowed("2130706433")))
        XCTAssertEqual(try verdict("https://8.8.8.8/x"), .deny(.ipLiteralNotAllowed("8.8.8.8")))
        // Other spellings of local addresses are not classed, but are still denied as IP literals.
        for url in ["https://[::ffff:127.0.0.1]/x", "https://[::ffff:c0a8:114]/x", "https://[0:0:0:0:0:0:0:1]/x", "https://0x7f.1/x"] {
            guard case .deny(.ipLiteralNotAllowed) = try verdict(url) else { return XCTFail("\(url) must be denied as an IP literal") }
        }
        // An exact rule can still name a private address deliberately.
        XCTAssertEqual(try verdict("https://10.0.0.5:8443/x"), .allow)
    }

    func testRejectsMalformedAndNonASCIIHosts() throws {
        // URLComponents parses "not a url" as a relative reference with no scheme.
        XCTAssertEqual(try verdict("not a url"), .deny(.schemeNotAllowed("")))
        // URLComponents percent-encodes a non-ASCII host; the host syntax check refuses `%`.
        XCTAssertEqual(try verdict("https://аpi.example.com/"), .deny(.malformedURL("https://аpi.example.com/")))
        XCTAssertEqual(try verdict("https://api%2Eexample.com/"), .deny(.malformedURL("https://api%2Eexample.com/")))
        XCTAssertEqual(try verdict("https:///nohost"), .deny(.malformedURL("https:///nohost")))
    }

    func testRuleConstructionValidates() {
        XCTAssertThrowsError(try HostRule.exact("", port: 443))
        XCTAssertThrowsError(try HostRule.exact("api.example.com", port: 0))
        XCTAssertThrowsError(try HostRule.exact("api.example.com", port: 70_000))
        XCTAssertThrowsError(try HostRule.exact("a..b"))
        XCTAssertThrowsError(try HostRule.exact("*.example.com"))
        XCTAssertThrowsError(try HostRule.includingSubdomains(of: "10.0.0.1")) { error in
            XCTAssertEqual(error as? HostRuleError, .domainRuleOnIPLiteral("10.0.0.1"))
        }
        XCTAssertThrowsError(try HostRule.includingSubdomains(of: "com")) { error in
            XCTAssertEqual(error as? HostRuleError, .domainRuleTooBroad("com"))
        }
        XCTAssertNoThrow(try HostRule.exact("localhost")) // an exact single-label rule names one host
        XCTAssertThrowsError(try HostRule.exact("api.example.com:8443")) // a port typed into the host is not an IPv6 literal
        XCTAssertNoThrow(try HostRule.exact("[fd00::1]"))
    }
}

final class FileRuleTests: XCTestCase {
    private let gate = PolicyGate()

    private func manifest() throws -> CapabilityManifest {
        CapabilityManifest(
            fileGrants: [
                try FileGrant("/App/Docs", .readOnly),
                try FileGrant("/App/Docs/Drafts", .readWrite),
            ],
            keychainServices: ["com.example.allowed"],
            appGroups: ["group.com.example.allowed"],
            reviewSuffixes: [".TOKEN"]
        )
    }

    func testReadAnywhereInGrantsWriteOnlyWhereReadWrite() throws {
        let m = try manifest()
        XCTAssertEqual(gate.evaluate(.file(path: "/App/Docs/a.md", access: .read), under: m, resolver: LexicalResolver()), .allow)
        XCTAssertEqual(gate.evaluate(.file(path: "/App/Docs/a.md", access: .write), under: m, resolver: LexicalResolver()),
                       .deny(.writeNotGranted("/App/Docs/a.md")))
        XCTAssertEqual(gate.evaluate(.file(path: "/App/Docs/Drafts/a.md", access: .write), under: m, resolver: LexicalResolver()), .allow)
        XCTAssertEqual(gate.evaluate(.file(path: "/App/Other/a.md", access: .read), under: m, resolver: LexicalResolver()),
                       .deny(.outsideFileGrants("/App/Other/a.md")))
    }

    func testParentReferencesAreDeniedOutright() throws {
        let outcome = gate.evaluate(.file(path: "/App/Docs/../Secrets/key", access: .read), under: try manifest(), resolver: LexicalResolver())
        XCTAssertEqual(outcome, .deny(.invalidPath(String(describing: PathError.parentReference("/App/Docs/../Secrets/key")))))
        // The bypass this closes: `link/..` would collapse to a path inside the grant
        // as text, while the kernel walks `..` from wherever the link points.
        let resolver = SymlinkTableResolver(links: [try SandboxPath("/App/Docs/link"): try SandboxPath("/App/Secrets/inner")])
        guard case .deny(.invalidPath) = gate.evaluate(.file(path: "/App/Docs/link/../key", access: .read), under: try manifest(), resolver: resolver) else {
            return XCTFail("link/.. must be denied")
        }
        if case .deny(.invalidPath) = gate.evaluate(.file(path: "Docs/a", access: .read), under: try manifest(), resolver: LexicalResolver()) {} else {
            XCTFail("relative paths must be denied as invalid")
        }
    }

    func testSymlinkPointingOutsideIsDeniedEvenThoughLexicalPathIsInside() throws {
        let resolver = SymlinkTableResolver(links: [try SandboxPath("/App/Docs/link"): try SandboxPath("/App/Secrets")])
        let outcome = gate.evaluate(.file(path: "/App/Docs/link/key", access: .read), under: try manifest(), resolver: resolver)
        XCTAssertEqual(outcome, .deny(.symlinkEscape(lexical: "/App/Docs/link/key", resolved: "/App/Secrets/key")))
    }

    func testSymlinkThatStaysInsideIsAllowed() throws {
        let resolver = SymlinkTableResolver(links: [try SandboxPath("/App/Docs/latest"): try SandboxPath("/App/Docs/Drafts")])
        XCTAssertEqual(gate.evaluate(.file(path: "/App/Docs/latest/a.md", access: .read), under: try manifest(), resolver: resolver), .allow)
    }

    func testWriteThroughLinkIntoReadOnlyPartIsDenied() throws {
        // Lexically in the writable Drafts grant, physically in the read-only part.
        let resolver = SymlinkTableResolver(links: [try SandboxPath("/App/Docs/Drafts/up"): try SandboxPath("/App/Docs")])
        let outcome = gate.evaluate(.file(path: "/App/Docs/Drafts/up/a.md", access: .write), under: try manifest(), resolver: resolver)
        XCTAssertEqual(outcome, .deny(.symlinkEscape(lexical: "/App/Docs/Drafts/up/a.md", resolved: "/App/Docs/a.md")))
    }

    func testDeepestGrantDecidesTheModeSoNestedReadOnlyStaysReadOnly() throws {
        let m = CapabilityManifest(fileGrants: [try FileGrant("/W", .readWrite), try FileGrant("/W/Reference", .readOnly)])
        XCTAssertEqual(gate.evaluate(.file(path: "/W/Reference/style.md", access: .write), under: m, resolver: LexicalResolver()),
                       .deny(.writeNotGranted("/W/Reference/style.md")))
        XCTAssertEqual(gate.evaluate(.file(path: "/W/Reference/style.md", access: .read), under: m, resolver: LexicalResolver()), .allow)
        XCTAssertEqual(gate.evaluate(.file(path: "/W/notes.md", access: .write), under: m, resolver: LexicalResolver()), .allow)
        // Writing through a link from the writable part into the nested read-only part.
        let resolver = SymlinkTableResolver(links: [try SandboxPath("/W/ref-link"): try SandboxPath("/W/Reference")])
        XCTAssertEqual(gate.evaluate(.file(path: "/W/ref-link/style.md", access: .write), under: m, resolver: resolver),
                       .deny(.symlinkEscape(lexical: "/W/ref-link/style.md", resolved: "/W/Reference/style.md")))
        // And the converse, which the case rule above can't mask: read-write nested in read-only.
        let rwInRo = CapabilityManifest(fileGrants: [try FileGrant("/D", .readOnly), try FileGrant("/D/Out", .readWrite)])
        XCTAssertEqual(gate.evaluate(.file(path: "/D/Out/x", access: .write), under: rwInRo, resolver: LexicalResolver()), .allow)
        // The same root listed twice with different modes: the restrictive one wins.
        let dup = CapabilityManifest(fileGrants: [try FileGrant("/D", .readWrite), try FileGrant("/D", .readOnly)])
        XCTAssertEqual(gate.evaluate(.file(path: "/D/x", access: .write), under: dup, resolver: LexicalResolver()), .deny(.writeNotGranted("/D/x")))
    }

    func testCaseVariantOfANestedReadOnlyGrantIsStillReadOnly() throws {
        // On a case-insensitive volume /W/reference IS /W/Reference.
        let m = CapabilityManifest(fileGrants: [try FileGrant("/W", .readWrite), try FileGrant("/W/Reference", .readOnly)])
        XCTAssertEqual(gate.evaluate(.file(path: "/W/reference/style.md", access: .write), under: m, resolver: LexicalResolver()),
                       .deny(.writeNotGranted("/W/reference/style.md")))
        XCTAssertEqual(gate.evaluate(.file(path: "/W/reference/style.md", access: .read), under: m, resolver: LexicalResolver()), .allow)
        // A case variant never makes a path "inside": on a case-sensitive volume it is another directory.
        let only = CapabilityManifest(fileGrants: [try FileGrant("/Docs/Reference", .readOnly)])
        XCTAssertEqual(gate.evaluate(.file(path: "/Docs/reference/x.md", access: .read), under: only, resolver: LexicalResolver()),
                       .deny(.outsideFileGrants("/Docs/reference/x.md")))
    }

    func testGrantRootThatIsItselfALinkIsJudgedByItsPhysicalLocation() throws {
        let m = CapabilityManifest(fileGrants: [try FileGrant("/App/Current", .readWrite)])
        let resolver = SymlinkTableResolver(links: [try SandboxPath("/App/Current"): try SandboxPath("/App/Versions/7")])
        XCTAssertEqual(gate.evaluate(.file(path: "/App/Current/a.md", access: .write), under: m, resolver: resolver), .allow)
    }

    func testReviewSuffixOnTheLinkTargetIsFlaggedToo() throws {
        let resolver = SymlinkTableResolver(links: [try SandboxPath("/App/Docs/notes.md"): try SandboxPath("/App/Docs/Drafts/session.token")])
        let outcome = gate.evaluate(.file(path: "/App/Docs/notes.md", access: .read), under: try manifest(), resolver: resolver)
        guard case .needsReview = outcome else { return XCTFail("a benign name linking to a flagged file must be reviewed, got \(outcome)") }
    }

    func testReviewReasonStaysBoundedForManyFlaggedResources() throws {
        let resources = (0..<1_000).map { Resource.file(path: "/App/Docs/\($0).token", access: .read) }
        guard case let .needsReview(flags) = gate.evaluate(resources, under: try manifest(), resolver: LexicalResolver()) else {
            return XCTFail("expected needsReview")
        }
        XCTAssertEqual(flags.count, 1_000, "the verdict keeps every flag in full")
        let summary = ReviewFlag.summary(flags)
        XCTAssertLessThan(summary.count, 1_000, "the text shown to people stays bounded")
        XCTAssertTrue(summary.hasSuffix("and 997 more"))
    }

    func testReviewSuffixIsCaseInsensitiveAndFlagsInsteadOfAllowing() throws {
        let outcome = gate.evaluate(.file(path: "/App/Docs/Session.Token", access: .read), under: try manifest(), resolver: LexicalResolver())
        guard case .needsReview = outcome else { return XCTFail("expected needsReview, got \(outcome)") }
    }

    func testKeychainAndAppGroupsAreDenyByDefault() throws {
        let m = try manifest()
        XCTAssertEqual(gate.evaluate(.keychain(service: "com.example.allowed"), under: m, resolver: LexicalResolver()), .allow)
        XCTAssertEqual(gate.evaluate(.keychain(service: "com.example.auth"), under: m, resolver: LexicalResolver()), .deny(.keychainForbidden("com.example.auth")))
        XCTAssertEqual(gate.evaluate(.appGroup(identifier: "group.com.example.allowed"), under: m, resolver: LexicalResolver()), .allow)
        XCTAssertEqual(gate.evaluate(.appGroup(identifier: "group.other"), under: m, resolver: LexicalResolver()), .deny(.appGroupForbidden("group.other")))
    }

    func testEmptyManifestDeniesEverything() {
        let empty = CapabilityManifest()
        for resource: Resource in [.file(path: "/a", access: .read), .network(url: "https://example.com"), .keychain(service: "s"), .appGroup(identifier: "g")] {
            guard case .deny = gate.evaluate(resource, under: empty, resolver: LexicalResolver()) else {
                return XCTFail("\(resource) must be denied by an empty manifest")
            }
        }
    }
}
