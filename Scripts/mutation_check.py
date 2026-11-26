#!/usr/bin/env python3
"""Mutation check: break each load-bearing guard on purpose and require that the
named test FAILS. A guard whose mutant still passes its test is not tested.

Run from the package root: python3 Scripts/mutation_check.py
Each mutant is applied to the file and reverted in a `finally`, including on
Ctrl-C or SIGTERM.
"""
import pathlib
import re
import signal
import subprocess
import sys

SRC = pathlib.Path("Sources/AgentSandbox")

MUTANTS = [
    (
        "containment by string prefix",
        SRC / "Paths/SandboxPath.swift",
        "return zip(root.components, components).allSatisfy { $0 == $1 }",
        "return string.hasPrefix(root.string)",
        "SandboxPathTests/testContainmentIsByComponentNotStringPrefix",
    ),
    (
        "`..` collapsed as text instead of rejected",
        SRC / "Paths/SandboxPath.swift",
        "throw PathError.parentReference(raw.clamped(to: 80))",
        "if !parts.isEmpty { parts.removeLast() }",
        "FileRuleTests/testParentReferencesAreDeniedOutright",
    ),
    (
        "link targets collapsed as text",
        SRC / "Paths/PathResolving.swift",
        "pending = (target + Array(pending))[...]",
        "var collapsed: [String] = []; for t in target { if t == \"..\" { if !collapsed.isEmpty { collapsed.removeLast() } } else if t != \".\" { collapsed.append(t) } }; pending = (collapsed + Array(pending))[...]",
        "ResolverTests/testFileSystemResolverFollowsRealAbsoluteAndRelativeLinks",
    ),
    (
        "symlink target not checked",
        SRC / "Policy/PolicyGate.swift",
        "Self.decidingMode(for: physical, among: physicalRoots)",
        "Self.decidingMode(for: lexical, among: physicalRoots)",
        "FileRuleTests/testSymlinkPointingOutsideIsDeniedEvenThoughLexicalPathIsInside",
    ),
    (
        "shallowest grant decides the mode",
        SRC / "Policy/PolicyGate.swift",
        "if depth > current.depth ||",
        "if depth < current.depth ||",
        "FileRuleTests/testReadAnywhereInGrantsWriteOnlyWhereReadWrite",
    ),
    (
        "grant roots not resolved",
        SRC / "Policy/PolicyGate.swift",
        "(try? resolver.resolve(grant.root)).map { (grant, $0) }",
        "Optional(grant.root).map { (grant, $0) }",
        "FileRuleTests/testGrantRootThatIsItselfALinkIsJudgedByItsPhysicalLocation",
    ),
    (
        "review suffix ignored",
        SRC / "Policy/PolicyGate.swift",
        "guard flagged.isEmpty else {",
        "guard flagged.isEmpty || true else {",
        "FileRuleTests/testReviewSuffixIsCaseInsensitiveAndFlagsInsteadOfAllowing",
    ),
    (
        "review suffix checked on the lexical name only",
        SRC / "Policy/PolicyGate.swift",
        "[lexical.lastComponent, physical.lastComponent]",
        "[lexical.lastComponent]",
        "FileRuleTests/testReviewSuffixOnTheLinkTargetIsFlaggedToo",
    ),
    (
        "subdomain match without a label boundary",
        SRC / "Network/HostRule.swift",
        'return candidate == host || candidate.hasSuffix("." + host)',
        "return candidate.hasSuffix(host)",
        "NetworkRuleTests/testSubdomainRuleMatchesOnLabelBoundaryOnly",
    ),
    (
        "user info in URL accepted",
        SRC / "Policy/PolicyGate.swift",
        "guard parts.user == nil, parts.password == nil else { return .deny(.credentialsInURL) }",
        "",
        "NetworkRuleTests/testDeniesPlainHTTPAndUserInfo",
    ),
    (
        "no manifest-epoch re-check after review",
        SRC / "Runtime/ToolRuntime.swift",
        "guard epoch == startEpoch else { return deny(call, .manifestChanged, phase: .beforeRun, detail: detail) }",
        "_ = startEpoch",
        "ToolRuntimeTests/testManifestReplacedDuringReviewDeniesTheParkedCall",
    ),
    (
        "no lock re-check after review",
        SRC / "Runtime/ToolRuntime.swift",
        "if isLocked { return deny(call, .sessionLocked(denials: denials), phase: .beforeRun, detail: detail) }",
        "",
        "ToolRuntimeTests/testSessionLockedDuringReviewDeniesTheParkedCall",
    ),
    (
        "rules not re-run after review",
        SRC / "Runtime/ToolRuntime.swift",
        "switch evaluator.evaluate(resources, under: manifest, resolver: resolver) {\n            case .needsReview(flags):",
        "switch RuleOutcome.needsReview(flags) {\n            case .needsReview(flags):",
        "ToolRuntimeTests/testSymlinkSwappedWhileParkedInReviewIsCaughtByTheRecheck",
    ),
    (
        "flagged access allowed mid-run",
        SRC / "Runtime/ToolRuntime.swift",
        "case let .needsReview(flags):\n            let reason = DenialReason.reviewUnavailable(ReviewFlag.summary(flags))\n            _ = deny(call, reason, phase: .duringRun, detail: resource.description)\n            throw SandboxDenial(reason: reason)",
        "case .needsReview:\n            record(call, .duringRun, detail: resource.description, .allowed)",
        "ToolRuntimeTests/testFlaggedAccessDuringRunIsDeniedAndCounted",
    ),
    (
        "smuggled context still authorizes",
        SRC / "Runtime/ToolRuntime.swift",
        "guard activeRuns.contains(runToken) else {",
        "guard activeRuns.contains(runToken) || true else {",
        "ToolRuntimeTests/testContextSmuggledOutOfItsCallIsInert",
    ),
    (
        'classifier failure counts toward lockout',
        SRC / "Policy/Resource.swift",
        'case .classifierUnavailable, .manifestChanged, .verdictChangedDuringReview, .callNotActive, .sessionLocked:',
        'case .manifestChanged, .verdictChangedDuringReview, .callNotActive, .sessionLocked:',
        'ToolRuntimeTests/testClassifierAllowDenyAndThrow',
    ),
    (
        'manifest swap counts toward lockout',
        SRC / "Policy/Resource.swift",
        'case .classifierUnavailable, .manifestChanged, .verdictChangedDuringReview, .callNotActive, .sessionLocked:',
        'case .classifierUnavailable, .verdictChangedDuringReview, .callNotActive, .sessionLocked:',
        'ToolRuntimeTests/testManifestReplacedDuringReviewDeniesTheParkedCall',
    ),
    (
        'changed verdict counts toward lockout',
        SRC / "Policy/Resource.swift",
        'case .classifierUnavailable, .manifestChanged, .verdictChangedDuringReview, .callNotActive, .sessionLocked:',
        'case .classifierUnavailable, .manifestChanged, .callNotActive, .sessionLocked:',
        'ToolRuntimeTests/testLinkRepointedToAnotherFlaggedFileDuringReviewIsDenied',
    ),
    (
        'late authorize counts toward lockout',
        SRC / "Policy/Resource.swift",
        'case .classifierUnavailable, .manifestChanged, .verdictChangedDuringReview, .callNotActive, .sessionLocked:',
        'case .classifierUnavailable, .manifestChanged, .verdictChangedDuringReview, .sessionLocked:',
        'ToolRuntimeTests/testContextSmuggledOutOfItsCallIsInert',
    ),
    (
        'lock refusals keep counting',
        SRC / "Policy/Resource.swift",
        'case .classifierUnavailable, .manifestChanged, .verdictChangedDuringReview, .callNotActive, .sessionLocked:',
        'case .classifierUnavailable, .manifestChanged, .verdictChangedDuringReview, .callNotActive:',
        'ToolRuntimeTests/testSessionLocksAfterMaxDenialsAndThenRefusesEvenAllowedCalls',
    ),
    (
        'case variant of a read-only grant ignored',
        SRC / "Policy/PolicyGate.swift",
        'if caseVariantReadOnly { return .readOnly }',
        '_ = caseVariantReadOnly',
        'FileRuleTests/testCaseVariantOfANestedReadOnlyGrantIsStillReadOnly',
    ),
    (
        'resolved path left out of the review flag',
        SRC / "Policy/PolicyGate.swift",
        'ReviewFlag(access: access, lexical: lexical, physical: physical,',
        'ReviewFlag(access: access, lexical: lexical, physical: lexical,',
        'ToolRuntimeTests/testLinkRepointedToAnotherFlaggedFileDuringReviewIsDenied',
    ),
    (
        'reports written into the audit ring',
        SRC / "Runtime/ToolRuntime.swift",
        '        reports.append(report)\n        return .gapReported(report)',
        '        reports.append(report)\n        record(call, .duringRun, detail: needed, .allowed)\n        return .gapReported(report)',
        'ToolRuntimeTests/testReportsCannotEvictDenialsFromTheAuditTrail',
    ),
    (
        'digest encodes sets unsorted',
        SRC / "Manifest/CapabilityManifest.swift",
        'let grants = fileGrants.sorted()',
        'let grants = Array(fileGrants)',
        'ManifestDigestTests/testDigestIsSortedSoEveryConstructionHistoryAgrees',
    ),
    (
        'prompt renders sets unsorted',
        SRC / "Manifest/SandboxPromptRenderer.swift",
        'let grants = manifest.fileGrants.sorted()',
        'let grants = Array(manifest.fileGrants)',
        'PromptRendererTests/testPromptListsGrantsAndHostsInSortedOrder',
    ),
    (
        "re-check compares only the bounded summary",
        SRC / "Runtime/ToolRuntime.swift",
        "case .needsReview(flags):",
        "case let .needsReview(now) where ReviewFlag.summary(now) == ReviewFlag.summary(flags):",
        "ToolRuntimeTests/testRepointingTheFourthOfFourFlaggedLinksDuringReviewIsDenied",
    ),
    (
        "default resolver ignores links",
        SRC / "Runtime/ToolRuntime.swift",
        "resolver: any PathResolving = FileSystemResolver(),",
        "resolver: any PathResolving = LexicalResolver(),",
        "ToolRuntimeTests/testDefaultResolverFollowsRealLinks",
    ),
    (
        "hop limit configurable away",
        SRC / "Paths/PathResolving.swift",
        "self.maxHops = min(max(1, maxHops), Self.hopLimit)",
        "self.maxHops = max(1, maxHops)",
        "ResolverTests/testHopLimitCannotBeConfiguredAway",
    ),
]


def main() -> int:
    # Turn SIGTERM into an exception so the `finally` below restores the file.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(130))
    survivors = []
    for name, path, old, new, test in MUTANTS:
        original = path.read_text()
        if original.count(old) != 1:
            print(f"SETUP ERROR [{name}]: expected exactly one match in {path}")
            return 2
        try:
            path.write_text(original.replace(old, new))
            result = subprocess.run(
                ["swift", "test", "--filter", test],
                capture_output=True, text=True,
            )
        finally:
            path.write_text(original)
        output = result.stdout + result.stderr
        # A filter that matches no test would let every mutant "survive" silently.
        if re.search(r"Executed 0 tests", output):
            print(f"SETUP ERROR [{name}]: filter {test} matched no tests")
            return 2
        # A mutant only counts as caught if it compiled and a test actually failed;
        # a build error would otherwise masquerade as a kill.
        if not re.search(r"Executed \d+ tests?, with [1-9]\d* failures?", output):
            if result.returncode != 0:
                print(f"SETUP ERROR [{name}]: mutant did not build or run tests\n{output[-2000:]}")
                return 2
        caught = result.returncode != 0
        print(f"{'caught  ' if caught else 'SURVIVED'} {name}  ({test})")
        if not caught:
            survivors.append(name)
    if survivors:
        print(f"\n{len(survivors)} mutant(s) survived: {survivors}")
        return 1
    print(f"\nAll {len(MUTANTS)} mutants were caught by their tests.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
