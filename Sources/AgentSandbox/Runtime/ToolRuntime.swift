/// How many agent-attributable denials a session tolerates before it locks.
public struct LockoutPolicy: Hashable, Sendable {
    /// `nil` means never lock. Used by the evaluation harness for its ablations.
    public let maxDenials: Int?

    /// Values below 1 are raised to 1: a policy that locks before any denial
    /// would refuse every call and is never what the caller meant.
    public init(maxDenials: Int) {
        self.maxDenials = max(1, maxDenials)
    }

    private init(unbounded: Void) {
        self.maxDenials = nil
    }

    public static let disabled = LockoutPolicy(unbounded: ())
}

/// A tool's name and one-line summary, as rendered into the system prompt.
public struct ToolSummary: Hashable, Sendable {
    public let name: String
    public let summary: String

    public init(name: String, summary: String) {
        self.name = name
        self.summary = summary
    }
}

public enum RuntimeConfigurationError: Error, Equatable, Sendable {
    case emptyToolName
    case duplicateToolName(String)
    case reservedToolName(String)
}

/// The agent filed a structured incident instead of working around a boundary.
public struct BoundaryGapReport: Sendable, Equatable {
    public let sequence: UInt64
    public let callID: String
    public let needed: String
    public let reason: String
    public let manifestDigest: String
}

public enum CallOutcome: Sendable, Equatable {
    case executed(output: String)
    case denied(DenialReason)
    case gapReported(BoundaryGapReport)
    /// The call never reached the gate: bad arguments for a known tool. The
    /// string is safe to show the model (a missing-argument message, or a generic
    /// one); the tool's full error stays in the audit trail.
    case rejected(String)
    /// Allowed, ran, and the tool itself threw.
    case failed(String)

    public var wasExecuted: Bool {
        if case .executed = self { return true }
        return false
    }

    /// The text to hand back to the model as the tool result.
    public var agentFacingText: String {
        switch self {
        case let .executed(output): return output
        case let .denied(reason): return reason.agentFacingMessage
        case let .gapReported(report): return "Recorded boundary gap report \(report.sequence) for the app to review. Continue with what you can do inside the sandbox."
        case let .rejected(why): return "Rejected: \(why)."
        case .failed: return "The tool failed."
        }
    }
}

public struct AuditEntry: Sendable, Equatable {
    public enum Phase: String, Sendable {
        /// The declared resources, judged before the tool ran.
        case beforeRun
        /// An access requested from inside a running tool.
        case duringRun
        /// The tool ran and then threw.
        case afterRun
    }

    public enum Verdict: Sendable, Equatable {
        case allowed
        case denied(DenialReason)
        case rejected(String)
        case failed(String)
    }

    public let sequence: UInt64
    public let callID: String
    public let tool: String
    public let phase: Phase
    public let detail: String
    public let verdict: Verdict
    public let manifestEpoch: UInt64
    public let manifestDigest: String
}

/// A point-in-time copy of everything the runtime has recorded.
public struct RuntimeSnapshot: Sendable, Equatable {
    public let audit: [AuditEntry]
    public let droppedAuditEntries: Int
    public let reports: [BoundaryGapReport]
    public let droppedReports: Int
    public let denials: Int
    public let isLocked: Bool
    public let manifestEpoch: UInt64
    public let manifestDigest: String
}

/// One agent session's tool runtime: the only path from a model's tool call to a
/// side effect.
///
/// Order of checks for `execute(_:)`: session lock → known tool → declared
/// resources → deterministic rules → (only if flagged) classifier → run.
///
/// Actor reentrancy: the classifier and the tool body are the only suspension
/// points. After the classifier returns, the runtime re-checks the manifest epoch
/// and the lock before running anything, because another call (or the host app)
/// may have changed either while this one was suspended. A denial is never
/// converted to an allow by a later step.
public actor ToolRuntime {
    public static let reportToolName = "report_boundary_gap"
    public static let maxReportFieldLength = 512

    private var manifest: CapabilityManifest
    /// Cached: the digest sorts every field, and every audit entry carries it.
    private var manifestDigest: String
    private var epoch: UInt64 = 0
    private let tools: [String: any SandboxTool]
    public nonisolated let toolSummaries: [ToolSummary]
    private let evaluator: any AccessEvaluating
    private let resolver: any PathResolving
    private let classifier: (any CallClassifier)?
    public nonisolated let lockout: LockoutPolicy

    private var denials = 0
    /// Calls whose tool body is running. `ToolContext.authorize(_:)` is refused for
    /// any other token, so a context smuggled out of its call is inert.
    private var activeRuns: Set<UInt64> = []
    private var nextRunToken: UInt64 = 0
    private var sequence: UInt64 = 0
    private var audit: BoundedLog<AuditEntry>
    private var reports: BoundedLog<BoundaryGapReport>

    public init(
        manifest: CapabilityManifest,
        tools: [any SandboxTool],
        evaluator: any AccessEvaluating = PolicyGate(),
        resolver: any PathResolving = FileSystemResolver(),
        classifier: (any CallClassifier)? = nil,
        lockout: LockoutPolicy = LockoutPolicy(maxDenials: 3),
        logCapacity: Int = 256
    ) throws {
        var byName: [String: any SandboxTool] = [:]
        var summaries: [ToolSummary] = []
        for tool in tools {
            guard !tool.name.isEmpty else { throw RuntimeConfigurationError.emptyToolName }
            guard tool.name != Self.reportToolName else { throw RuntimeConfigurationError.reservedToolName(tool.name) }
            guard byName[tool.name] == nil else { throw RuntimeConfigurationError.duplicateToolName(tool.name) }
            byName[tool.name] = tool
            summaries.append(ToolSummary(name: tool.name, summary: tool.summary))
        }
        self.manifest = manifest
        self.manifestDigest = manifest.digest
        self.tools = byName
        self.toolSummaries = summaries
        self.evaluator = evaluator
        self.resolver = resolver
        self.classifier = classifier
        self.lockout = lockout
        self.audit = BoundedLog(capacity: logCapacity)
        self.reports = BoundedLog(capacity: logCapacity)
    }

    // MARK: State

    public var isLocked: Bool {
        guard let limit = lockout.maxDenials else { return false }
        return denials >= limit
    }

    public var currentManifest: CapabilityManifest { manifest }

    /// The sandbox section of the system prompt for the manifest in force now.
    public func systemPrompt() -> String {
        SandboxPromptRenderer.render(manifest: manifest, tools: toolSummaries, lockout: lockout)
    }

    /// Replace (typically narrow) the manifest mid-session. Any call suspended in
    /// review when this happens is denied with `.manifestChanged`.
    public func replaceManifest(_ newManifest: CapabilityManifest) {
        manifest = newManifest
        manifestDigest = newManifest.digest
        epoch &+= 1 // UInt64: wrapping is unreachable in practice and harmless if it happened
    }

    public func snapshot() -> RuntimeSnapshot {
        RuntimeSnapshot(
            audit: audit.elements,
            droppedAuditEntries: audit.dropped,
            reports: reports.elements,
            droppedReports: reports.dropped,
            denials: denials,
            isLocked: isLocked,
            manifestEpoch: epoch,
            manifestDigest: manifestDigest
        )
    }

    // MARK: Execution

    public func execute(_ call: ToolCall) async -> CallOutcome {
        if call.tool == Self.reportToolName { return fileReport(call) }
        if isLocked { return deny(call, .sessionLocked(denials: denials), phase: .beforeRun) }
        guard let tool = tools[call.tool] else {
            return deny(call, .unknownTool(call.tool.clamped(to: 80)), phase: .beforeRun)
        }

        let resources: [Resource]
        do { resources = try tool.declaredResources(for: call.arguments) } catch {
            let why = String(describing: error).clamped(to: 200)
            record(call, .beforeRun, detail: "arguments", .rejected(why))
            // Only argument errors are echoed to the model; anything else a tool's
            // resource closure throws could carry details the agent should not see.
            let agentSafe = (error as? ToolArgumentError)?.description ?? "invalid arguments for \(tool.name)"
            return .rejected(agentSafe)
        }

        let startEpoch = epoch
        let judgedManifest = manifest
        let detail = resources.map(\.description).joined(separator: ", ")

        switch evaluator.evaluate(resources, under: judgedManifest, resolver: resolver) {
        case let .deny(reason):
            return deny(call, reason, phase: .beforeRun, detail: detail)
        case let .needsReview(flags):
            guard let classifier else {
                return deny(call, .reviewUnavailable(ReviewFlag.summary(flags)), phase: .beforeRun, detail: detail)
            }
            let request = ReviewRequest(call: call, resources: resources, flags: flags, manifestDigest: manifestDigest)
            let decision: ClassifierDecision
            do { decision = try await classifier.classify(request) } catch {
                return deny(call, .classifierUnavailable, phase: .beforeRun, detail: detail)
            }
            // --- suspension point above: re-validate everything that may have moved ---
            guard epoch == startEpoch else { return deny(call, .manifestChanged, phase: .beforeRun, detail: detail) }
            if isLocked { return deny(call, .sessionLocked(denials: denials), phase: .beforeRun, detail: detail) }
            if case let .deny(why) = decision {
                return deny(call, .classifierDenied(why.clamped(to: 200)), phase: .beforeRun, detail: detail)
            }
            // The rules depend on the resolver (the file system), which may have
            // changed while the call was parked. The classifier approved one verdict;
            // run anything else and it is unreviewed.
            switch evaluator.evaluate(resources, under: manifest, resolver: resolver) {
            case .needsReview(flags):
                break // exactly the flags that were reviewed, compared in full
            case let .deny(reason):
                return deny(call, reason, phase: .beforeRun, detail: detail)
            case .allow, .needsReview:
                return deny(call, .verdictChangedDuringReview, phase: .beforeRun, detail: detail)
            }
        case .allow:
            break
        }

        record(call, .beforeRun, detail: detail, .allowed)
        nextRunToken &+= 1 // UInt64: wrapping is unreachable in practice
        let token = nextRunToken
        activeRuns.insert(token)
        defer { activeRuns.remove(token) }
        let context = ToolContext(callID: call.id, toolName: call.tool, runToken: token, runtime: self)
        do {
            let output = try await tool.run(call.arguments, context: context)
            return .executed(output: output)
        } catch let denial as SandboxDenial {
            // Already recorded and counted by authorizeDuringRun.
            return .denied(denial.reason)
        } catch {
            let why = String(describing: error).clamped(to: 200)
            record(call, .afterRun, detail: detail, .failed(why))
            return .failed(why)
        }
    }

    func authorizeDuringRun(_ resource: Resource, callID: String, toolName: String, runToken: UInt64) throws {
        let call = ToolCall(id: callID, tool: toolName)
        guard activeRuns.contains(runToken) else {
            _ = deny(call, .callNotActive, phase: .duringRun, detail: resource.description)
            throw SandboxDenial(reason: .callNotActive)
        }
        if isLocked {
            let reason = DenialReason.sessionLocked(denials: denials)
            _ = deny(call, reason, phase: .duringRun, detail: resource.description)
            throw SandboxDenial(reason: reason)
        }
        switch evaluator.evaluate(resource, under: manifest, resolver: resolver) {
        case .allow:
            record(call, .duringRun, detail: resource.description, .allowed)
        case let .deny(reason):
            _ = deny(call, reason, phase: .duringRun, detail: resource.description)
            throw SandboxDenial(reason: reason)
        case let .needsReview(flags):
            let reason = DenialReason.reviewUnavailable(ReviewFlag.summary(flags))
            _ = deny(call, reason, phase: .duringRun, detail: resource.description)
            throw SandboxDenial(reason: reason)
        }
    }

    // MARK: Recording

    private func deny(_ call: ToolCall, _ unclamped: DenialReason, phase: AuditEntry.Phase, detail: String = "") -> CallOutcome {
        let reason = unclamped.clamped()
        if reason.countsTowardLockout { denials = denials.saturatingAdd(1) }
        record(call, phase, detail: detail, .denied(reason))
        return .denied(reason)
    }

    /// Reports go to their own bounded ring and never into the audit trail, so an
    /// agent that files reports (which are free and uncounted) cannot push its
    /// denials out of the audit ring. Sequence numbers are shared, so the two
    /// logs interleave in one order.
    private func fileReport(_ call: ToolCall) -> CallOutcome {
        let needed = (call.arguments["needed"] ?? "").clamped(to: Self.maxReportFieldLength)
        let reason = (call.arguments["reason"] ?? "").clamped(to: Self.maxReportFieldLength)
        guard !needed.isEmpty else {
            return .rejected("\(Self.reportToolName) needs a 'needed' argument")
        }
        sequence &+= 1
        let report = BoundaryGapReport(
            sequence: sequence, callID: call.id.clamped(to: 80), needed: needed, reason: reason, manifestDigest: manifestDigest
        )
        reports.append(report)
        return .gapReported(report)
    }

    private func record(_ call: ToolCall, _ phase: AuditEntry.Phase, detail: String, _ verdict: AuditEntry.Verdict) {
        sequence &+= 1
        audit.append(AuditEntry(
            sequence: sequence,
            callID: call.id.clamped(to: 80),
            tool: call.tool.clamped(to: 80),
            phase: phase,
            detail: detail.clamped(to: 300),
            verdict: verdict,
            manifestEpoch: epoch,
            manifestDigest: manifestDigest
        ))
    }
}
