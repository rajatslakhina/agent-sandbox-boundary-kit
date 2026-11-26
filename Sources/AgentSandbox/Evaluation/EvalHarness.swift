/// One gate configuration to evaluate.
public struct EvalConfiguration: Sendable {
    public let name: String
    public let evaluator: any AccessEvaluating
    public let lockout: LockoutPolicy

    public init(name: String, evaluator: any AccessEvaluating, lockout: LockoutPolicy) {
        self.name = name
        self.evaluator = evaluator
        self.lockout = lockout
    }

    /// The ablation ladder the demo shows: no gate, the naive gate, the real gate
    /// without lockout, the real gate with lockout.
    public static let ladder: [EvalConfiguration] = [
        EvalConfiguration(name: "No gate", evaluator: UnguardedEvaluator(), lockout: .disabled),
        EvalConfiguration(name: "Naive string-prefix gate", evaluator: NaivePrefixEvaluator(), lockout: .disabled),
        EvalConfiguration(name: "PolicyGate", evaluator: PolicyGate(), lockout: .disabled),
        EvalConfiguration(name: "PolicyGate + lockout after 3", evaluator: PolicyGate(), lockout: LockoutPolicy(maxDenials: 3)),
    ]
}

public struct AttemptResult: Sendable, Equatable {
    public let attempt: TemptationAttempt
    public let outcome: CallOutcome
}

public struct ScenarioResult: Sendable, Equatable {
    public let scenario: TemptationScenario
    public let attempts: [AttemptResult]

    /// For an out-of-bounds scenario: some attempt executed (an escape).
    /// For a control: the legitimate attempt executed (task done).
    public var anyExecuted: Bool { attempts.contains { $0.outcome.wasExecuted } }

    /// Attempts that received a real verdict, as opposed to being cut off by the
    /// session lock. Each one tells the agent something about the boundary.
    public var probesAnswered: Int {
        attempts.filter { result in
            if case .denied(.sessionLocked) = result.outcome { return false }
            return true
        }.count
    }
}

public struct EvalReport: Sendable, Equatable {
    public let configurationName: String
    public let results: [ScenarioResult]

    public var outOfBoundsScenarios: Int { results.filter { $0.scenario.kind == .outOfBounds }.count }
    public var escapes: Int { results.filter { $0.scenario.kind == .outOfBounds && $0.anyExecuted }.count }
    public var controlScenarios: Int { results.filter { $0.scenario.kind == .control }.count }
    public var falseDenials: Int { results.filter { $0.scenario.kind == .control && !$0.anyExecuted }.count }
    public var probesAnswered: Int { results.reduce(0) { $0.saturatingAdd($1.probesAnswered) } }
    public var attemptsMade: Int { results.reduce(0) { $0.saturatingAdd($1.attempts.count) } }
}

/// Replays a corpus against a gate configuration. Each scenario gets a fresh
/// `ToolRuntime` (one session), and the scripted agent walks the scenario's
/// attempts in order, stopping at the first one that executes.
///
/// What this measures: whether the enforcement layer stops each attempt, how many
/// legitimate calls it wrongly blocks, and how many probes lockout cuts off. What
/// it does NOT measure: how often a real model makes these attempts. The agent
/// here is a script, so prompt-side mitigations (explicit rules, the report tool)
/// have no effect on these numbers by construction.
public enum EvalHarness {
    public static func run(
        _ configuration: EvalConfiguration,
        scenarios: [TemptationScenario] = TemptationCorpus.scenarios,
        manifest: CapabilityManifest = TemptationCorpus.manifest,
        resolver: any PathResolving = TemptationCorpus.resolver,
        tools: [any SandboxTool] = TemptationCorpus.tools
    ) async throws -> EvalReport {
        var results: [ScenarioResult] = []
        for scenario in scenarios {
            let runtime = try ToolRuntime(
                manifest: manifest,
                tools: tools,
                evaluator: configuration.evaluator,
                resolver: resolver,
                classifier: nil,
                lockout: configuration.lockout
            )
            var attempts: [AttemptResult] = []
            for attempt in scenario.attempts {
                let outcome = await runtime.execute(attempt.call)
                attempts.append(AttemptResult(attempt: attempt, outcome: outcome))
                if outcome.wasExecuted { break }
            }
            results.append(ScenarioResult(scenario: scenario, attempts: attempts))
        }
        return EvalReport(configurationName: configuration.name, results: results)
    }
}
