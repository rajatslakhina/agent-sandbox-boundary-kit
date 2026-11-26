import Foundation
import XCTest
@testable import AgentSandbox

/// Counts how many times tool bodies actually ran.
actor RunCounter {
    private(set) var runs = 0
    func bump() { runs += 1 }
}

/// A classifier that parks inside `classify` until the test releases it, so the
/// test can change runtime state across the suspension point.
struct ParkedClassifier: CallClassifier {
    let entered: AsyncStream<Void>.Continuation
    let release: AsyncStream<Void>
    let decision: ClassifierDecision

    func classify(_ request: ReviewRequest) async throws -> ClassifierDecision {
        entered.yield()
        for await _ in release { break }
        return decision
    }
}

/// A resolver whose link table the test can swap while a call is parked.
final class SwitchableResolver: PathResolving, @unchecked Sendable {
    private let lock = NSLock()
    private var table: SymlinkTableResolver

    init(_ links: [SandboxPath: SandboxPath]) { table = SymlinkTableResolver(links: links) }

    func swap(to links: [SandboxPath: SandboxPath]) {
        lock.lock(); defer { lock.unlock() }
        table = SymlinkTableResolver(links: links)
    }

    func resolve(_ path: SandboxPath) throws -> SandboxPath {
        lock.lock(); defer { lock.unlock() }
        return try table.resolve(path)
    }
}

/// Holds a context a misbehaving tool smuggled out of its call.
actor ContextStash {
    var context: ToolContext?
    func keep(_ c: ToolContext) { context = c }
}

struct ThrowingClassifier: CallClassifier {
    struct Boom: Error {}
    func classify(_ request: ReviewRequest) async throws -> ClassifierDecision { throw Boom() }
}

final class ToolRuntimeTests: XCTestCase {
    private func manifest() throws -> CapabilityManifest {
        CapabilityManifest(
            fileGrants: [try FileGrant("/W", .readWrite)],
            hosts: [try .exact("api.example.com")],
            reviewSuffixes: [".token"]
        )
    }

    private func readTool(_ counter: RunCounter) -> DeclarativeTool {
        DeclarativeTool(
            name: "read_file", summary: "Read a file.",
            resources: { [.file(path: try DeclarativeTool.require("path", in: $0), access: .read)] },
            body: { args, _ in await counter.bump(); return "read \(args["path"] ?? "")" }
        )
    }

    private func read(_ path: String, id: String = "c") -> ToolCall {
        ToolCall(id: id, tool: "read_file", arguments: ["path": path])
    }

    func testAllowedCallRunsAndIsAudited() async throws {
        let counter = RunCounter()
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [readTool(counter)])
        let outcome = await runtime.execute(read("/W/a.md"))
        XCTAssertEqual(outcome, .executed(output: "read /W/a.md"))
        let runs = await counter.runs
        XCTAssertEqual(runs, 1)
        let snap = await runtime.snapshot()
        XCTAssertEqual(snap.audit.count, 1)
        XCTAssertEqual(snap.audit.first?.verdict, .allowed)
        XCTAssertEqual(snap.audit.first?.manifestDigest, try manifest().digest)
    }

    func testDeniedCallNeverRunsTheToolBody() async throws {
        let counter = RunCounter()
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [readTool(counter)])
        let outcome = await runtime.execute(read("/etc/passwd"))
        XCTAssertEqual(outcome, .denied(.outsideFileGrants("/etc/passwd")))
        let runs = await counter.runs
        XCTAssertEqual(runs, 0)
    }

    func testSessionLocksAfterMaxDenialsAndThenRefusesEvenAllowedCalls() async throws {
        let counter = RunCounter()
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [readTool(counter)], lockout: LockoutPolicy(maxDenials: 2))
        _ = await runtime.execute(read("/x"))
        let lockedAfterOne = await runtime.isLocked
        XCTAssertFalse(lockedAfterOne)
        _ = await runtime.execute(ToolCall(id: "u", tool: "no_such_tool"))
        let lockedAfterTwo = await runtime.isLocked
        XCTAssertTrue(lockedAfterTwo, "unknown tools are probes and count")
        let outcome = await runtime.execute(read("/W/a.md"))
        XCTAssertEqual(outcome, .denied(.sessionLocked(denials: 2)))
        let runs = await counter.runs
        XCTAssertEqual(runs, 0)
        let denials = await runtime.snapshot().denials
        XCTAssertEqual(denials, 2, "lock-refusals do not keep counting")
    }

    func testDisabledLockoutNeverLocks() async throws {
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [readTool(RunCounter())], lockout: .disabled)
        for i in 0..<50 { _ = await runtime.execute(read("/x\(i)")) }
        let locked = await runtime.isLocked
        XCTAssertFalse(locked)
        XCTAssertEqual(LockoutPolicy(maxDenials: -4).maxDenials, 1)
    }

    func testReportToolWorksWhileLockedAndDoesNotCount() async throws {
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [readTool(RunCounter())], lockout: LockoutPolicy(maxDenials: 1))
        _ = await runtime.execute(read("/x"))
        let outcome = await runtime.execute(ToolCall(id: "r", tool: ToolRuntime.reportToolName,
                                                     arguments: ["needed": "read /Caches/session.token", "reason": "the task asks for the current session"]))
        guard case let .gapReported(report) = outcome else { return XCTFail("expected a report, got \(outcome)") }
        XCTAssertEqual(report.needed, "read /Caches/session.token")
        let snap = await runtime.snapshot()
        XCTAssertEqual(snap.reports, [report])
        XCTAssertEqual(snap.denials, 1)
        XCTAssertGreaterThan(report.sequence, snap.audit.last?.sequence ?? 0, "reports share the sequence")
    }

    func testReportsCannotEvictDenialsFromTheAuditTrail() async throws {
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [readTool(RunCounter())], lockout: .disabled, logCapacity: 4)
        _ = await runtime.execute(read("/escape", id: "deny"))
        for i in 0..<50 {
            _ = await runtime.execute(ToolCall(id: "r\(i)", tool: ToolRuntime.reportToolName, arguments: ["needed": "x"]))
        }
        _ = await runtime.execute(ToolCall(id: "bad", tool: ToolRuntime.reportToolName)) // rejected, also not audited
        let snap = await runtime.snapshot()
        XCTAssertEqual(snap.audit.map(\.callID), ["deny"])
        XCTAssertEqual(snap.droppedAuditEntries, 0)
        XCTAssertEqual(snap.reports.count, 4)
        XCTAssertEqual(snap.droppedReports, 46)
    }

    func testReportToolRequiresNeededAndClampsFieldLength() async throws {
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [])
        let missing = await runtime.execute(ToolCall(id: "r", tool: ToolRuntime.reportToolName, arguments: ["reason": "x"]))
        guard case .rejected = missing else { return XCTFail("expected rejection, got \(missing)") }
        let long = String(repeating: "n", count: ToolRuntime.maxReportFieldLength * 3)
        let outcome = await runtime.execute(ToolCall(id: "r2", tool: ToolRuntime.reportToolName, arguments: ["needed": long, "reason": long]))
        guard case let .gapReported(report) = outcome else { return XCTFail("expected a report") }
        XCTAssertEqual(report.needed.count, ToolRuntime.maxReportFieldLength)
        XCTAssertEqual(report.reason.count, ToolRuntime.maxReportFieldLength)
    }

    func testMissingArgumentIsRejectedNotCountedAsDenial() async throws {
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [readTool(RunCounter())], lockout: LockoutPolicy(maxDenials: 1))
        let outcome = await runtime.execute(ToolCall(id: "c", tool: "read_file"))
        XCTAssertEqual(outcome, .rejected("missing argument 'path'"))
        let locked = await runtime.isLocked
        XCTAssertFalse(locked)
    }

    func testNonArgumentErrorsFromAToolAreNotEchoedToTheModel() async throws {
        struct Leaky: Error, CustomStringConvertible { var description: String { "/private/var/secret/path not found" } }
        let tool = DeclarativeTool(name: "leaky", summary: "", resources: { _ in throw Leaky() }, body: { _, _ in "" })
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [tool])
        let outcome = await runtime.execute(ToolCall(id: "l", tool: "leaky"))
        XCTAssertEqual(outcome, .rejected("invalid arguments for leaky"))
        let audit = await runtime.snapshot().audit
        XCTAssertEqual(audit.last?.verdict, .rejected("/private/var/secret/path not found"), "the audit keeps the real error")
    }

    func testToolThatThrowsAfterRunningIsAuditedAsAfterRun() async throws {
        struct Boom: Error {}
        let tool = DeclarativeTool(name: "boom", summary: "", resources: { _ in [] }, body: { _, _ in throw Boom() })
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [tool])
        let outcome = await runtime.execute(ToolCall(id: "b", tool: "boom"))
        guard case .failed = outcome else { return XCTFail("got \(outcome)") }
        let audit = await runtime.snapshot().audit
        XCTAssertEqual(audit.map(\.phase), [.beforeRun, .afterRun])
    }

    func testFlaggedAccessDuringRunIsDeniedAndCounted() async throws {
        let tool = DeclarativeTool(
            name: "peek", summary: "", resources: { _ in [] },
            body: { _, context in try await context.authorize(.file(path: "/W/session.token", access: .read)); return "peeked" }
        )
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [tool],
                                      classifier: ToolTrustClassifier(trustedTools: ["peek"]), lockout: LockoutPolicy(maxDenials: 1))
        let outcome = await runtime.execute(ToolCall(id: "p", tool: "peek"))
        guard case .denied(.reviewUnavailable) = outcome else { return XCTFail("review is only offered up front; got \(outcome)") }
        let locked = await runtime.isLocked
        XCTAssertTrue(locked)
    }

    func testContextSmuggledOutOfItsCallIsInert() async throws {
        let stash = ContextStash()
        let tool = DeclarativeTool(name: "smuggle", summary: "", resources: { _ in [] },
                                   body: { _, context in await stash.keep(context); return "done" })
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [tool], lockout: LockoutPolicy(maxDenials: 1))
        _ = await runtime.execute(ToolCall(id: "s", tool: "smuggle"))
        guard let late = await stash.context else { return XCTFail("tool did not run") }
        do {
            try await late.authorize(.file(path: "/W/inside.md", access: .read)) // would be allowed during the call
            XCTFail("authorize after the call ended must throw")
        } catch let denial as SandboxDenial {
            XCTAssertEqual(denial.reason, .callNotActive)
        }
        let snap = await runtime.snapshot()
        XCTAssertFalse(snap.isLocked, "a tool bug is not the agent's denial")
        XCTAssertFalse(snap.audit.contains { $0.phase == .duringRun && $0.verdict == .allowed })
    }

    func testSymlinkSwappedWhileParkedInReviewIsCaughtByTheRecheck() async throws {
        let counter = RunCounter()
        let (enteredStream, entered) = AsyncStream<Void>.makeStream()
        let (release, releaser) = AsyncStream<Void>.makeStream()
        let resolver = SwitchableResolver([:])
        let runtime = try ToolRuntime(
            manifest: try manifest(), tools: [readTool(counter)], resolver: resolver,
            classifier: ParkedClassifier(entered: entered, release: release, decision: .allow)
        )
        let parked = read("/W/link/session.token")
        let call = Task { await runtime.execute(parked) }
        for await _ in enteredStream { break }
        resolver.swap(to: [try SandboxPath("/W/link"): try SandboxPath("/Secrets")]) // the attacker repoints the link
        releaser.yield()
        let outcome = await call.value
        XCTAssertEqual(outcome, .denied(.symlinkEscape(lexical: "/W/link/session.token", resolved: "/Secrets/session.token")))
        let runs = await counter.runs
        XCTAssertEqual(runs, 0)
    }

    func testRepointingTheFourthOfFourFlaggedLinksDuringReviewIsDenied() async throws {
        // The text summary lists only three flags; the re-check must compare all of them.
        let (enteredStream, entered) = AsyncStream<Void>.makeStream()
        let (release, releaser) = AsyncStream<Void>.makeStream()
        var links: [SandboxPath: SandboxPath] = [:]
        for i in 1...4 { links[try SandboxPath("/W/l\(i).token")] = try SandboxPath("/W/t\(i).token") }
        let resolver = SwitchableResolver(links)
        let counter = RunCounter()
        let multi = DeclarativeTool(
            name: "read_many", summary: "",
            resources: { _ in (1...4).map { .file(path: "/W/l\($0).token", access: .read) } },
            body: { _, _ in await counter.bump(); return "read" }
        )
        let runtime = try ToolRuntime(
            manifest: try manifest(), tools: [multi], resolver: resolver,
            classifier: ParkedClassifier(entered: entered, release: release, decision: .allow)
        )
        let call = Task { await runtime.execute(ToolCall(id: "m", tool: "read_many")) }
        for await _ in enteredStream { break }
        links[try SandboxPath("/W/l4.token")] = try SandboxPath("/W/vault.token")
        resolver.swap(to: links)
        releaser.yield()
        let outcome = await call.value
        XCTAssertEqual(outcome, .denied(.verdictChangedDuringReview))
        let runs = await counter.runs
        XCTAssertEqual(runs, 0)
    }

    func testRepointingBeyondTwoHundredCharactersDuringReviewIsDenied() async throws {
        // Two targets that share their first 200+ characters and differ after.
        let (enteredStream, entered) = AsyncStream<Void>.makeStream()
        let (release, releaser) = AsyncStream<Void>.makeStream()
        let deep = "/W/" + Array(repeating: "folder", count: 40).joined(separator: "/")
        let link = try SandboxPath("/W/current.token")
        let resolver = SwitchableResolver([link: try SandboxPath(deep + "/a.token")])
        let counter = RunCounter()
        let runtime = try ToolRuntime(
            manifest: try manifest(), tools: [readTool(counter)], resolver: resolver,
            classifier: ParkedClassifier(entered: entered, release: release, decision: .allow)
        )
        let parked = read("/W/current.token")
        let call = Task { await runtime.execute(parked) }
        for await _ in enteredStream { break }
        resolver.swap(to: [link: try SandboxPath(deep + "/b.token")])
        releaser.yield()
        let outcome = await call.value
        XCTAssertEqual(outcome, .denied(.verdictChangedDuringReview))
        let runs = await counter.runs
        XCTAssertEqual(runs, 0)
    }

    func testDefaultResolverFollowsRealLinks() async throws {
        let fm = FileManager.default
        let base = fm.temporaryDirectory.appendingPathComponent("agent-sandbox-default-\(UUID().uuidString)")
        let workspace = base.appendingPathComponent("Workspace")
        let outside = base.appendingPathComponent("Caches")
        try fm.createDirectory(at: workspace, withIntermediateDirectories: true)
        try fm.createDirectory(at: outside, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: base) }
        try fm.createSymbolicLink(atPath: workspace.appendingPathComponent("link").path, withDestinationPath: outside.path)
        let m = CapabilityManifest(fileGrants: [try FileGrant(workspace.path, .readWrite)])
        let runtime = try ToolRuntime(manifest: m, tools: [readTool(RunCounter())]) // no resolver: argument
        let outcome = await runtime.execute(read(workspace.path + "/link/session.token"))
        guard case .denied(.symlinkEscape) = outcome else { return XCTFail("the default resolver must follow links; got \(outcome)") }
    }

    func testCredentialsInAURLNeverReachTheAuditTrail() async throws {
        let fetch = DeclarativeTool(name: "http_get", summary: "",
                                    resources: { [.network(url: try DeclarativeTool.require("url", in: $0))] },
                                    body: { _, _ in "" })
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [fetch])
        _ = await runtime.execute(ToolCall(id: "c", tool: "http_get", arguments: ["url": "https://alice:hunter2@api.example.com/v1"]))
        // Unparseable (non-numeric port) with credentials: denied as malformed, and still redacted.
        let outcome = await runtime.execute(ToolCall(id: "d", tool: "http_get", arguments: ["url": "https://alice:hunter2@api.example.com:abc/"]))
        guard case .denied(.malformedURL) = outcome else { return XCTFail("got \(outcome)") }
        XCTAssertFalse(String(describing: outcome).contains("hunter2"))
        let audit = await runtime.snapshot().audit
        XCTAssertEqual(audit.count, 2)
        XCTAssertFalse(audit.contains { $0.detail.contains("hunter2") || $0.detail.contains("alice") })
        XCTAssertFalse(audit.contains { String(describing: $0.verdict).contains("hunter2") })
        XCTAssertTrue(audit.first?.detail.contains("api.example.com") ?? false)
    }

    func testReportFieldsAreBoundedByScalarsNotGraphemes() async throws {
        // One grapheme cluster: "a" followed by 100,000 combining acute accents.
        let heavy = "a" + String(repeating: "\u{301}", count: 100_000)
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [])
        let outcome = await runtime.execute(ToolCall(id: "h", tool: ToolRuntime.reportToolName, arguments: ["needed": heavy]))
        guard case let .gapReported(report) = outcome else { return XCTFail("got \(outcome)") }
        XCTAssertEqual(report.needed.unicodeScalars.count, ToolRuntime.maxReportFieldLength)
        XCTAssertLessThanOrEqual(report.needed.utf8.count, ToolRuntime.maxReportFieldLength * 4)
    }

    func testAuthorizeDuringRunSeesAManifestNarrowedWhileTheToolRuns() async throws {
        let (enteredStream, entered) = AsyncStream<Void>.makeStream()
        let (release, releaser) = AsyncStream<Void>.makeStream()
        let tool = DeclarativeTool(
            name: "slow_writer", summary: "", resources: { _ in [] },
            body: { _, context in
                entered.yield()
                for await _ in release { break }
                try await context.authorize(.file(path: "/W/out.json", access: .write))
                return "wrote"
            }
        )
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [tool])
        let call = Task { await runtime.execute(ToolCall(id: "w", tool: "slow_writer")) }
        for await _ in enteredStream { break } // the body is running
        await runtime.replaceManifest(CapabilityManifest(fileGrants: [try FileGrant("/W", .readOnly)]))
        releaser.yield()
        let outcome = await call.value
        XCTAssertEqual(outcome, .denied(.writeNotGranted("/W/out.json")), "judged against the manifest as it is now")
    }

    func testAuditedDenialReasonsAreClamped() async throws {
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [readTool(RunCounter())], lockout: .disabled)
        let longPath = "/" + Array(repeating: "segment", count: 200).joined(separator: "/")
        let outcome = await runtime.execute(read(longPath))
        guard case let .denied(.outsideFileGrants(shown)) = outcome else { return XCTFail("got \(outcome)") }
        XCTAssertEqual(shown.count, 300)
    }

    func testConfigurationErrors() throws {
        let counter = RunCounter()
        XCTAssertThrowsError(try ToolRuntime(manifest: CapabilityManifest(), tools: [readTool(counter), readTool(counter)])) {
            XCTAssertEqual($0 as? RuntimeConfigurationError, .duplicateToolName("read_file"))
        }
        let reserved = DeclarativeTool(name: ToolRuntime.reportToolName, summary: "", resources: { _ in [] }, body: { _, _ in "" })
        XCTAssertThrowsError(try ToolRuntime(manifest: CapabilityManifest(), tools: [reserved])) {
            XCTAssertEqual($0 as? RuntimeConfigurationError, .reservedToolName(ToolRuntime.reportToolName))
        }
        let unnamed = DeclarativeTool(name: "", summary: "", resources: { _ in [] }, body: { _, _ in "" })
        XCTAssertThrowsError(try ToolRuntime(manifest: CapabilityManifest(), tools: [unnamed]))
    }

    func testFlaggedCallWithoutClassifierFailsClosed() async throws {
        let counter = RunCounter()
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [readTool(counter)], lockout: LockoutPolicy(maxDenials: 1))
        let outcome = await runtime.execute(read("/W/session.token"))
        guard case .denied(.reviewUnavailable) = outcome else { return XCTFail("got \(outcome)") }
        let runs = await counter.runs
        XCTAssertEqual(runs, 0)
        let locked = await runtime.isLocked
        XCTAssertTrue(locked, "asking for a flagged file with no reviewer configured counts")
    }

    func testClassifierAllowDenyAndThrow() async throws {
        let counter = RunCounter()
        let trusting = try ToolRuntime(manifest: try manifest(), tools: [readTool(counter)],
                                       classifier: ToolTrustClassifier(trustedTools: ["read_file"]))
        let allowed = await trusting.execute(read("/W/session.token"))
        XCTAssertEqual(allowed, .executed(output: "read /W/session.token"))

        let distrusting = try ToolRuntime(manifest: try manifest(), tools: [readTool(counter)],
                                          classifier: ToolTrustClassifier(trustedTools: []), lockout: LockoutPolicy(maxDenials: 1))
        let denied = await distrusting.execute(read("/W/session.token"))
        guard case .denied(.classifierDenied) = denied else { return XCTFail("got \(denied)") }
        let lockedByDenial = await distrusting.isLocked
        XCTAssertTrue(lockedByDenial, "a classifier denial counts")

        let throwing = try ToolRuntime(manifest: try manifest(), tools: [readTool(counter)],
                                       classifier: ThrowingClassifier(), lockout: LockoutPolicy(maxDenials: 1))
        let failed = await throwing.execute(read("/W/session.token"))
        XCTAssertEqual(failed, .denied(.classifierUnavailable))
        let locked = await throwing.isLocked
        XCTAssertFalse(locked, "a broken classifier is not the agent's fault")

        let runs = await counter.runs
        XCTAssertEqual(runs, 1, "only the trusted call ran")
    }

    func testClassifierNeverSeesDeterministicDenials() async throws {
        // A classifier that would allow everything still cannot rescue a denied path.
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [readTool(RunCounter())],
                                      classifier: ToolTrustClassifier(trustedTools: ["read_file"]))
        let outcome = await runtime.execute(read("/Caches/session.token"))
        XCTAssertEqual(outcome, .denied(.outsideFileGrants("/Caches/session.token")))
    }

    func testManifestReplacedDuringReviewDeniesTheParkedCall() async throws {
        let counter = RunCounter()
        let (enteredStream, entered) = AsyncStream<Void>.makeStream()
        let (release, releaser) = AsyncStream<Void>.makeStream()
        let runtime = try ToolRuntime(
            manifest: try manifest(), tools: [readTool(counter)],
            classifier: ParkedClassifier(entered: entered, release: release, decision: .allow),
            lockout: LockoutPolicy(maxDenials: 1)
        )
        let parked = read("/W/session.token")
        let call = Task { await runtime.execute(parked) }
        for await _ in enteredStream { break } // the call is now suspended in review
        await runtime.replaceManifest(CapabilityManifest()) // revoke everything
        releaser.yield()
        let outcome = await call.value
        XCTAssertEqual(outcome, .denied(.manifestChanged))
        let runs = await counter.runs
        XCTAssertEqual(runs, 0)
        let locked = await runtime.isLocked
        XCTAssertFalse(locked, "the host's manifest swap is not the agent's denial")
    }

    func testLinkRepointedToAnotherFlaggedFileDuringReviewIsDenied() async throws {
        let counter = RunCounter()
        let (enteredStream, entered) = AsyncStream<Void>.makeStream()
        let (release, releaser) = AsyncStream<Void>.makeStream()
        let link = try SandboxPath("/W/current.token")
        let resolver = SwitchableResolver([link: try SandboxPath("/W/harmless.token")])
        let runtime = try ToolRuntime(
            manifest: try manifest(), tools: [readTool(counter)], resolver: resolver,
            classifier: ParkedClassifier(entered: entered, release: release, decision: .allow),
            lockout: LockoutPolicy(maxDenials: 1)
        )
        let parked = read("/W/current.token")
        let call = Task { await runtime.execute(parked) }
        for await _ in enteredStream { break }
        resolver.swap(to: [link: try SandboxPath("/W/vault.token")]) // still inside, still flagged, but not what was reviewed
        releaser.yield()
        let outcome = await call.value
        XCTAssertEqual(outcome, .denied(.verdictChangedDuringReview))
        let runs = await counter.runs
        XCTAssertEqual(runs, 0)
        let locked = await runtime.isLocked
        XCTAssertFalse(locked, "a link changing under review is not the agent's denial")
    }

    func testSessionLockedDuringReviewDeniesTheParkedCall() async throws {
        let counter = RunCounter()
        let (enteredStream, entered) = AsyncStream<Void>.makeStream()
        let (release, releaser) = AsyncStream<Void>.makeStream()
        let runtime = try ToolRuntime(
            manifest: try manifest(), tools: [readTool(counter)],
            classifier: ParkedClassifier(entered: entered, release: release, decision: .allow),
            lockout: LockoutPolicy(maxDenials: 2)
        )
        let parked = read("/W/session.token")
        let call = Task { await runtime.execute(parked) }
        for await _ in enteredStream { break }
        _ = await runtime.execute(read("/x1"))
        _ = await runtime.execute(read("/x2")) // locks while the first call is parked
        releaser.yield()
        let outcome = await call.value
        XCTAssertEqual(outcome, .denied(.sessionLocked(denials: 2)))
        let runs = await counter.runs
        XCTAssertEqual(runs, 0)
    }

    func testConcurrentDenialsLockAtExactlyTheLimit() async throws {
        let counter = RunCounter()
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [readTool(counter)], lockout: LockoutPolicy(maxDenials: 5))
        await withTaskGroup(of: Void.self) { group in
            for i in 0..<40 {
                group.addTask { _ = await runtime.execute(ToolCall(id: "\(i)", tool: "read_file", arguments: ["path": "/out/\(i)"])) }
                group.addTask { _ = await runtime.execute(ToolCall(id: "ok\(i)", tool: "read_file", arguments: ["path": "/W/\(i)"])) }
            }
        }
        let snap = await runtime.snapshot()
        XCTAssertEqual(snap.denials, 5)
        XCTAssertTrue(snap.isLocked)
        let runs = await counter.runs
        let allowed = snap.audit.filter { $0.verdict == .allowed }
        XCTAssertEqual(runs, allowed.count, "every run was audited as allowed, and nothing ran unaudited")
        // Whatever the interleaving, nothing is allowed after the denial that locked the session.
        let counted = snap.audit.filter {
            if case let .denied(reason) = $0.verdict { return reason.countsTowardLockout }
            return false
        }
        XCTAssertEqual(counted.count, 5)
        guard let lockingSequence = counted.last?.sequence else { return XCTFail("no locking denial") }
        XCTAssertTrue(allowed.allSatisfy { $0.sequence < lockingSequence })
    }

    func testDuringRunAuthorizationUsesTheCurrentManifestAndCounts() async throws {
        let fetcher = DeclarativeTool(
            name: "fetch_then_save", summary: "Fetch, then save.",
            resources: { _ in [.network(url: "https://api.example.com/v1")] },
            body: { args, context in
                try await context.authorize(.file(path: args["dest"] ?? "", access: .write))
                return "saved"
            }
        )
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [fetcher], lockout: LockoutPolicy(maxDenials: 1))
        let ok = await runtime.execute(ToolCall(id: "a", tool: "fetch_then_save", arguments: ["dest": "/W/out.json"]))
        XCTAssertEqual(ok, .executed(output: "saved"))
        let escaped = await runtime.execute(ToolCall(id: "b", tool: "fetch_then_save", arguments: ["dest": "/tmp/out.json"]))
        XCTAssertEqual(escaped, .denied(.outsideFileGrants("/tmp/out.json")))
        let snap = await runtime.snapshot()
        XCTAssertTrue(snap.isLocked)
        XCTAssertEqual(snap.audit.last?.phase, .duringRun)
        XCTAssertEqual(snap.audit.last?.tool, "fetch_then_save")
    }

    func testAgentFacingTextLeaksNoPathsOrHosts() async throws {
        let resolver = SymlinkTableResolver(links: [try SandboxPath("/W/link"): try SandboxPath("/Secrets/vault")])
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [readTool(RunCounter())], resolver: resolver)
        let outcome = await runtime.execute(read("/W/link/key"))
        guard case let .denied(reason) = outcome else { return XCTFail("got \(outcome)") }
        XCTAssertTrue(reason.description.contains("/Secrets/vault"), "the audit detail keeps the resolved target")
        XCTAssertFalse(outcome.agentFacingText.contains("/Secrets"), "the model does not learn where the link points")
        XCTAssertFalse(outcome.agentFacingText.contains("/W"))
        XCTAssertTrue(outcome.agentFacingText.contains(ToolRuntime.reportToolName))
    }

    func testAuditLogIsBoundedAndCountsDrops() async throws {
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [readTool(RunCounter())], lockout: .disabled, logCapacity: 4)
        for i in 0..<10 { _ = await runtime.execute(read("/W/\(i)", id: "\(i)")) }
        let snap = await runtime.snapshot()
        XCTAssertEqual(snap.audit.map(\.callID), ["6", "7", "8", "9"])
        XCTAssertEqual(snap.droppedAuditEntries, 6)
    }

    func testSystemPromptTracksReplacedManifest() async throws {
        let runtime = try ToolRuntime(manifest: try manifest(), tools: [readTool(RunCounter())])
        let before = await runtime.systemPrompt()
        XCTAssertTrue(before.contains(try manifest().digest))
        await runtime.replaceManifest(CapabilityManifest())
        let after = await runtime.systemPrompt()
        XCTAssertTrue(after.contains(CapabilityManifest().digest))
        let snap = await runtime.snapshot()
        XCTAssertEqual(snap.manifestEpoch, 1)
        XCTAssertEqual(snap.manifestDigest, CapabilityManifest().digest)
    }
}
