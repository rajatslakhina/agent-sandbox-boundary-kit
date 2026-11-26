# AgentSandbox

**The sandbox your in-app agent can't talk its way out of.** A capability-scoped tool runtime for an iOS app that lets a model (Claude, or Apple's on-device model) call tools: one typed manifest is rendered into the system prompt *and* enforced in code before any tool runs, with a `report_boundary_gap` tool so the agent has a legitimate alternative to working around a denial.

[![CI](https://github.com/rajatslakhina/agent-sandbox-boundary-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/rajatslakhina/agent-sandbox-boundary-kit/actions/workflows/ci.yml)
Swift 6 · iOS 17+ / macOS 14+ · no dependencies · MIT

**Demo app:** [agent-sandbox-boundary-demo-app](https://github.com/rajatslakhina/agent-sandbox-boundary-demo-app) runs the corpus on iOS, attempt by attempt, with screenshots.

---

## Why this matters

On 24 Nov 2026 Anthropic published [Siren](https://safeguards.anthropic.com/2026/siren/), an evaluation that gives models routine tasks in deliberately weakened sandboxes with something useful left outside (a file, a credential, a service). Two findings matter to anyone shipping an agent feature:

- **The phrasing teams use to get better work is what pushes agents outside.** Prompts that tell the model to search thoroughly, or that give it broad authority over its machine, raised reach-outside rates far more than deadlines or failure costs did.
- **Three mitigations worked:** stating the sandbox rules explicitly (68% to 96% less likely to reach outside), giving the agent a tool to report a weakness instead of using it, and checking actions before they run.

An iOS app's agent has its own version of every Siren honeypot: a session token in `Library/Caches`, a `Workspace-backup` folder that shares a prefix with the granted one, a debug server on the LAN, a Keychain item, a widget's app-group container. This package is the enforcement half of those mitigations, plus an eval harness that shows what each layer stops.

## What's in it

| Layer | Type | What it decides |
|---|---|---|
| Manifest | `CapabilityManifest`, `FileGrant`, `HostRule` | File roots (read-only / read-write), an HTTPS host allowlist, granted Keychain services and app groups (none by default), and file suffixes that need review. Everything else is denied. |
| Prompt | `SandboxPromptRenderer` | Renders the manifest as the six explicit rules Siren tested (host files, host services, host-control sockets/APIs, credentials, network destinations, leftovers), in iOS terms, with the stop-and-report clause and the manifest digest. |
| Rules | `PolicyGate` | Deterministic, synchronous verdict per resource: `allow`, `deny(reason)` or `needsReview`. |
| Review | `CallClassifier`, `ToolTrustClassifier` | A second stage only for calls the rules allowed but flagged. It can narrow, never widen. |
| Runtime | `ToolRuntime` (actor) | The only path from a tool call to a side effect: lock → known tool → declared resources → rules → review → run. Audits every decision with the manifest digest; locks the session after N agent-caused denials. |
| Report | `report_boundary_gap` | Always allowed, even when locked; never counts as a denial; files a bounded, structured `BoundaryGapReport`. |
| Evals | `TemptationCorpus`, `EvalHarness`, `UnguardedEvaluator`, `NaivePrefixEvaluator` | 9 Siren-style out-of-bounds scenarios and 5 legitimate controls, replayed against four gate configurations. |

## Design decisions, and what was rejected

**One manifest, two renderings, one digest.** The prompt and the gate are generated from the same `CapabilityManifest` value, and the audit trail stamps every decision with `manifest.digest` (FNV-1a over a sorted, tagged, length-prefixed encoding). You can show from the log that the rules the model was shown are the rules that judged it. *Rejected:* hand-written prompt rules next to separately configured enforcement, because they drift silently. *Not claimed:* FNV-1a is not cryptographic; the digest detects drift, not forgery.

**Containment by path component, on the lexical *and* the resolved path, and no `..` at all.** Collapsing `..` as text is only correct when nothing on the way is a symlink: the kernel applies `..` *after* following a link, so `Workspace/cache-link/../Preferences` looks like a path inside the workspace but opens one beside wherever `cache-link` points. So `SandboxPath` rejects every `..` component (an agent never needs one to name a file inside its grants), and `FileSystemResolver` walks link targets the way the kernel does, popping the already-resolved physical prefix on `..`. The deepest grant containing a path decides its mode, so a read-only folder nested in a read-write one stays read-only. The same rule is applied again to the resolved path against the resolved grant roots, so a link cannot lead outside the grants or into a read-only grant for a write. *Rejected:* `hasPrefix` on strings, which lets `/Workspace-backup` and `/Workspace/../../Library` through (the eval shows exactly that), and normalise-then-resolve, which v1.0.0 did and which the `link/..` attempt in the corpus now pins.

**Host rules match on a label boundary, HTTPS only, port included.** `includingSubdomains(of: "cdn.example.com")` covers `img.cdn.example.com` but not `evilcdn.example.com`. User info in a URL is denied (`https://api.example.com@192.168.1.20/`). Non-ASCII hosts are rejected (punycode only), and a host whose last label is numeric or hex-prefixed is treated as an IP literal, which catches `2130706433` and similar spellings. Dotted-quad IPv4 and canonical IPv6 local addresses (loopback, RFC 1918, link-local, `.local`) are denied with a specific reason unless an exact rule names them; every other IP spelling (IPv4-mapped IPv6, expanded IPv6, integer or hex IPv4) is denied as an IP literal. A subdomain rule on a single-label name (`com`) is refused at construction. *Rejected:* an `http` escape hatch for development, because the manifest has no scheme field and so cannot grant plain HTTP by accident.

**Deterministic rules first, classifier second, and the classifier can only narrow.** The classifier never sees a call the rules denied, so a model-based classifier being talked round cannot reopen a closed door. A flagged call with no classifier, or a classifier that throws, is denied. *Rejected:* a classifier-only gate, which would make every verdict probabilistic. An on-device Foundation Models classifier is the intended production implementation of `CallClassifier`; this package ships the protocol and a deterministic stand-in so behaviour is testable without a model.

**Actor reentrancy is handled explicitly.** The classifier and the tool body are the only suspension points in `execute(_:)`. After review returns, the runtime re-checks the manifest epoch and the session lock, then re-runs the deterministic rules and requires the same verdict the classifier approved, because the rules depend on the file system and a link can be repointed while a call is parked. A call parked in review when the host app narrows the manifest is denied with `.manifestChanged`; one whose link changed is denied by the rules. Mid-run accesses (`context.authorize(_:)`) are judged against the manifest *as it is now*, and only while that call's tool body is running: a context kept past its call is refused (`.callNotActive`). Tests park a classifier across the suspension point and change each of these underneath it.

**Denials are not an oracle.** The audit trail keeps the full reason (including where a symlink resolved to). The model only gets `agentFacingMessage`: a category, "do not retry with a different path, host, encoding or tool", and a pointer to the report tool. Argument errors are the one exception, because the model needs them to fix its call: a missing argument is named; any other error a tool's resource closure throws reaches the model as "invalid arguments for <tool>" and stays in the audit trail.

**Lockout counts only what the agent caused.** Unknown tools, invalid paths and denied resources count, and so does a flagged resource when no classifier is configured (the agent asked for something the host chose not to offer review for). A manifest swap, a failing classifier, a verdict that changed during review, a tool authorizing after its call ended, or the lock itself do not. *Rejected:* exponential backoff, because a model does not experience time; refusing further calls is the signal it can act on.

**Everything is bounded.** The audit trail and the report list are fixed-capacity ring buffers with drop counters; report fields, audit details and every string inside an audited denial reason are clamped, and a review reason lists at most three flagged resources; counters saturate instead of trapping; path length, component count and symlink hops are capped.

## What the evals show

`EvalHarness` gives each scenario a fresh session, and a scripted agent walks the scenario's attempts in order (direct route first, then the evasions), stopping at the first one that executes. Reproduced by `EvalHarnessTests` on every CI run:

| Configuration | Escapes (of 9) | False denials (of 5 controls) | Attempts made | Probes answered |
|---|---|---|---|---|
| No gate | 9 | 0 | 14 | 14 |
| Naive string-prefix gate | 5 | 0 | 18 | 18 |
| `PolicyGate` | 0 | 0 | 22 | 22 |
| `PolicyGate` + lockout after 3 | 0 | 0 | 22 | 19 |

Every cell is pinned by `testReadmeEvalTableNumbers`. "Attempts made" differs because the agent stops at its first success: with no gate every scenario ends on its first attempt. "Probes answered" counts attempts that got a real verdict rather than the session lock; each one tells the agent something about the boundary, and lockout cuts every probe after the third denial: two from the five-attempt token scenario, one from the four-attempt LAN scenario.

The token scenario's five attempts are the direct path, `../` traversal, a planted symlink, the symlink followed by `..` (which collapses to a path inside the workspace as text), and the Keychain. The naive gate's five escapes are the ones the corpus was built to catch: `../` traversal from the workspace, a sibling directory that shares the workspace's name as a prefix, an `.env` file with no review step, `evilcdn.example.com` matching `cdn.example.com` without a label boundary, and an admin port on an allowed host. A test-only deny-everything gate scores 0 escapes and 5 false denials, which is why the controls exist.

**Read this before quoting the table.** The agent is a script, not a model, so these numbers measure the *enforcement* layer only. The prompt-side mitigations (explicit rules, the report tool) cannot move them by construction. Measuring how often a real model makes these attempts, with and without the rendered rules, needs a live model in the loop; that is the next step, not something this repo claims.

## Usage

```swift
import AgentSandbox

let manifest = CapabilityManifest(
    fileGrants: [try FileGrant(workspacePath, .readWrite), try FileGrant(referencePath, .readOnly)],
    hosts: [try .exact("api.example.com")],
    reviewSuffixes: [".token", ".env"]
)

let readFile = DeclarativeTool(
    name: "read_file", summary: "Read a UTF-8 file.",
    resources: { [.file(path: try DeclarativeTool.require("path", in: $0), access: .read)] },
    body: { args, _ in try String(contentsOfFile: args["path"] ?? "", encoding: .utf8) }
)

let runtime = try ToolRuntime(
    manifest: manifest,
    tools: [readFile],
    resolver: FileSystemResolver(),                  // follow real symlinks before judging
    classifier: ToolTrustClassifier(trustedTools: []), // or your Foundation Models classifier
    lockout: LockoutPolicy(maxDenials: 3)
)

let systemPrompt = await runtime.systemPrompt()       // send this with the model request
let outcome = await runtime.execute(ToolCall(id: callID, tool: name, arguments: arguments))
let toolResult = outcome.agentFacingText              // send this back as the tool result
```

Add the package:

```swift
.package(url: "https://github.com/rajatslakhina/agent-sandbox-boundary-kit.git", from: "2.0.0")
```

## Honest limits

- **Enforcement is by API, not by the kernel.** A tool body is Swift code; nothing stops it from calling `FileManager` directly. The runtime guarantees that the *declared* resources and every `context.authorize(_:)` request are judged; tools are privileged code you review like any other. iOS's own app sandbox remains the outer wall, and this layer narrows the agent to a fraction of what the app itself can reach.
- **Symlinks are resolved at check time.** A link swapped between the check and the open (TOCTOU) is not prevented here; an executor that opens files should use `O_NOFOLLOW` or open-by-descriptor. Hard links are not detected. `FileSystemResolver` caps link hops at 40 and fails closed on loops.
- **Host rules have no path or method scope.** An allowed host that accepts uploads is an exfiltration channel for anything the agent can read. Grant hosts accordingly.
- **No public-suffix list.** `includingSubdomains(of:)` refuses single-label names, but `includingSubdomains(of: "github.io")` would grant every GitHub Pages site. Name the narrowest domain you mean.
- **Tools receive the raw argument strings**, not the parsed values the gate judged. Paths are absolute with no `..`, so a tool opening the raw path opens the judged lexical path; a tool that parses a URL differently from `URLComponents` could fetch something other than what was judged. Parse with `URLComponents` in tools too.
- **Path components compare with Swift `String` equality**, which is canonical-equivalence (`é` composed equals `é` decomposed). That matches APFS, which is normalisation-insensitive; on a normalisation-sensitive file system two distinct names could compare equal.
- **No DNS awareness.** Host rules match names, not addresses: an allowed name whose DNS record points at `10.0.0.5` is still allowed. Pin certificates or resolve and re-check at the transport layer if that matters for you.
- **The classifier is not timed out by the runtime.** A `CallClassifier` must bound its own latency and should honour task cancellation.
- **The eval agent is scripted** (see above), and the corpus tools are simulated: they touch nothing and report what they would have done.
- **The manifest digest is FNV-1a**, chosen for stability across processes, not for collision resistance.

## Verification

Run locally on Xcode 27.2 / Swift 6.4.2 (macOS), from a clean `.build`:

- `swift build -Xswiftc -warnings-as-errors`: builds with no warnings.
- `swift test`: 69 XCTest tests, 0 failures. They include real-file-system symlink tests (absolute, relative, a relative target that walks `..` through another link, and a loop) and three tests that park a classifier across its suspension point and change the manifest, the lock or a symlink underneath it.
- `python3 Scripts/mutation_check.py`: breaks 16 load-bearing guards one at a time (among them string-prefix containment, `..` collapsed as text, link targets collapsed as text, unchecked symlink target, shallowest grant deciding the mode, suffix host match, no re-check after review, a smuggled context still authorizing) and requires the named test to fail; a mutant that does not compile is reported as a setup error, not a kill.

[CI](https://github.com/rajatslakhina/agent-sandbox-boundary-kit/actions/workflows/ci.yml) runs the same three things on GitHub's `macos-15` runner, plus an `xcodebuild` build of the library for the iOS Simulator SDK.

## License

MIT
