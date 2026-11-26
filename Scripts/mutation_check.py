#!/usr/bin/env python3
"""Mutation check: break each load-bearing guard on purpose and require that the
named test FAILS. A guard whose mutant still passes its test is not tested.

Run from the package root: python3 Scripts/mutation_check.py
Each mutant is applied to a pristine copy of the file and reverted afterwards,
even if the run is interrupted.
"""
import pathlib
import re
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
        "symlink target not checked",
        SRC / "Policy/PolicyGate.swift",
        "return physical.isWithin(physicalRoot)",
        "return physicalRoot == physicalRoot",
        "FileRuleTests/testSymlinkPointingOutsideIsDeniedEvenThoughLexicalPathIsInside",
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
        "host-caused denials count toward lockout",
        SRC / "Policy/Resource.swift",
        "case .classifierUnavailable, .manifestChanged, .sessionLocked: return false",
        "case .classifierUnavailable, .manifestChanged, .sessionLocked: return true",
        "ToolRuntimeTests/testClassifierAllowDenyAndThrow",
    ),
    (
        "review suffix ignored",
        SRC / "Policy/PolicyGate.swift",
        "guard flagged.isEmpty else {",
        "guard flagged.isEmpty || true else {",
        "FileRuleTests/testReviewSuffixIsCaseInsensitiveAndFlagsInsteadOfAllowing",
    ),
]


def main() -> int:
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
