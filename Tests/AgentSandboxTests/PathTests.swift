import Foundation
import XCTest
@testable import AgentSandbox

final class SandboxPathTests: XCTestCase {
    func testNormalisesDotsAndDuplicateSlashes() throws {
        XCTAssertEqual(try SandboxPath("/a//b/./c/d/").string, "/a/b/c/d")
        XCTAssertEqual(try SandboxPath("/").string, "/")
        XCTAssertEqual(try SandboxPath("/").components, [])
    }

    func testRejectsEveryParentReferenceInsteadOfCollapsingIt() {
        // Collapsing `link/..` as text is wrong once links exist; see SandboxPath.
        XCTAssertThrowsError(try SandboxPath("/a/../b")) { error in
            XCTAssertEqual(error as? PathError, .parentReference("/a/../b"))
        }
        XCTAssertThrowsError(try SandboxPath("/a/../../etc/passwd"))
        XCTAssertThrowsError(try SandboxPath("/.."))
        XCTAssertNoThrow(try SandboxPath("/a/..b/c..")) // only an exact `..` component is a parent reference
    }

    func testRejectsRelativeNULAndOversizedInput() {
        XCTAssertThrowsError(try SandboxPath("relative/path"))
        XCTAssertThrowsError(try SandboxPath(""))
        XCTAssertThrowsError(try SandboxPath("/a\u{0}b")) { XCTAssertEqual($0 as? PathError, .containsNUL) }
        XCTAssertThrowsError(try SandboxPath("/" + String(repeating: "a", count: SandboxPath.maxLength))) {
            XCTAssertEqual($0 as? PathError, .tooLong)
        }
        let deep = "/" + Array(repeating: "d", count: SandboxPath.maxComponents + 1).joined(separator: "/")
        XCTAssertThrowsError(try SandboxPath(deep)) { XCTAssertEqual($0 as? PathError, .tooManyComponents) }
    }

    func testCombiningMarkAfterSlashStillSplitsLikeTheKernel() throws {
        // "/" + U+0301 is ONE grapheme cluster; the kernel still splits on the 0x2F byte.
        XCTAssertThrowsError(try SandboxPath("/W/../\u{301}x")) { error in
            XCTAssertEqual(error as? PathError, .parentReference("/W/../\u{301}x"))
        }
        XCTAssertEqual(try SandboxPath("/W/a/\u{301}b").components, ["W", "a", "\u{301}b"])
    }

    func testContainmentIsByComponentNotStringPrefix() throws {
        let root = try SandboxPath("/App/Workspace")
        XCTAssertTrue(try SandboxPath("/App/Workspace").isWithin(root))
        XCTAssertTrue(try SandboxPath("/App/Workspace/a/b").isWithin(root))
        XCTAssertFalse(try SandboxPath("/App/Workspace-backup/a").isWithin(root))
        XCTAssertFalse(try SandboxPath("/App").isWithin(root))
        XCTAssertTrue(try SandboxPath("/anything").isWithin(SandboxPath("/")))
    }
}

final class ResolverTests: XCTestCase {
    func testTableResolverFollowsChainedLinks() throws {
        let resolver = SymlinkTableResolver(links: [
            try SandboxPath("/w/link"): try SandboxPath("/x"),
            try SandboxPath("/x/inner"): try SandboxPath("/y"),
        ])
        XCTAssertEqual(try resolver.resolve(SandboxPath("/w/link/inner/f")).string, "/y/f")
        XCTAssertEqual(try resolver.resolve(SandboxPath("/w/plain/f")).string, "/w/plain/f")
    }

    func testTableResolverBoundsLinkLoops() throws {
        let resolver = SymlinkTableResolver(links: [
            try SandboxPath("/a"): try SandboxPath("/b"),
            try SandboxPath("/b"): try SandboxPath("/a"),
        ], maxHops: 10)
        XCTAssertThrowsError(try resolver.resolve(SandboxPath("/a/f"))) { error in
            XCTAssertEqual(error as? ResolutionError, .tooManyLinks("/a/f"))
        }
    }

    func testFileSystemResolverFollowsRealAbsoluteAndRelativeLinks() throws {
        let fm = FileManager.default
        let base = fm.temporaryDirectory.appendingPathComponent("agent-sandbox-\(UUID().uuidString)")
        let workspace = base.appendingPathComponent("Workspace")
        let outside = base.appendingPathComponent("Caches")
        try fm.createDirectory(at: workspace, withIntermediateDirectories: true)
        try fm.createDirectory(at: outside, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: base) }
        try fm.createSymbolicLink(atPath: workspace.appendingPathComponent("abs").path, withDestinationPath: outside.path)
        try fm.createSymbolicLink(atPath: workspace.appendingPathComponent("rel").path, withDestinationPath: "../Caches")

        let resolver = FileSystemResolver()
        let physicalOutside = try resolver.resolve(SandboxPath(outside.path))
        let physicalWorkspace = try resolver.resolve(SandboxPath(workspace.path))
        for name in ["abs", "rel"] {
            let resolved = try resolver.resolve(SandboxPath(workspace.path + "/\(name)/session.token"))
            XCTAssertTrue(resolved.isWithin(physicalOutside), "\(name) -> \(resolved)")
            XCTAssertFalse(resolved.isWithin(physicalWorkspace), "\(name) -> \(resolved)")
        }
        // A relative link whose target walks `..` through ANOTHER link: the kernel
        // applies that `..` after following `s`, so `a` lands inside the outside
        // directory (next to `deep`), not inside the workspace. Text-collapsing `s/../x` would say
        // `Workspace/x` and wave it through.
        let deep = outside.appendingPathComponent("deep")
        try fm.createDirectory(at: deep, withIntermediateDirectories: true)
        try fm.createSymbolicLink(atPath: workspace.appendingPathComponent("s").path, withDestinationPath: deep.path)
        try fm.createSymbolicLink(atPath: workspace.appendingPathComponent("a").path, withDestinationPath: "s/../x")
        let viaParent = try resolver.resolve(SandboxPath(workspace.path + "/a"))
        XCTAssertEqual(viaParent, SandboxPath(normalisedComponents: physicalOutside.components + ["x"]))
        XCTAssertFalse(viaParent.isWithin(physicalWorkspace))

        // "/" followed by a combining mark must still be a component boundary, or the
        // resolver would never see `abs` as a link while the kernel follows it.
        let marked = try resolver.resolve(SandboxPath(workspace.path + "/abs/\u{301}x"))
        XCTAssertTrue(marked.isWithin(physicalOutside), "\(marked)")
        XCTAssertFalse(marked.isWithin(physicalWorkspace))
        // The same inside a link TARGET: `m` -> "abs/\u{301}y" must follow `abs`.
        try fm.createSymbolicLink(atPath: workspace.appendingPathComponent("m").path, withDestinationPath: "abs/\u{301}y")
        let viaTarget = try resolver.resolve(SandboxPath(workspace.path + "/m"))
        XCTAssertTrue(viaTarget.isWithin(physicalOutside), "\(viaTarget)")
        XCTAssertFalse(viaTarget.isWithin(physicalWorkspace))

        // A file that does not exist yet keeps its literal tail.
        let fresh = try resolver.resolve(SandboxPath(workspace.path + "/new/file.txt"))
        XCTAssertEqual(fresh.components.suffix(2), ["new", "file.txt"])
        XCTAssertTrue(fresh.isWithin(physicalWorkspace))
    }

    func testHopLimitCannotBeConfiguredAway() throws {
        XCTAssertEqual(FileSystemResolver(maxHops: .max).maxHops, FileSystemResolver.hopLimit)
        XCTAssertEqual(FileSystemResolver(maxHops: -3).maxHops, 1)
        let loop = SymlinkTableResolver(links: [
            try SandboxPath("/a"): try SandboxPath("/b"),
            try SandboxPath("/b"): try SandboxPath("/a"),
        ], maxHops: .max)
        XCTAssertEqual(loop.maxHops, FileSystemResolver.hopLimit)
        XCTAssertThrowsError(try loop.resolve(SandboxPath("/a/f"))) // terminates instead of spinning
    }

    func testFileSystemResolverBoundsRealLinkLoops() throws {
        let fm = FileManager.default
        let base = fm.temporaryDirectory.appendingPathComponent("agent-sandbox-loop-\(UUID().uuidString)")
        try fm.createDirectory(at: base, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: base) }
        try fm.createSymbolicLink(atPath: base.appendingPathComponent("a").path, withDestinationPath: "b")
        try fm.createSymbolicLink(atPath: base.appendingPathComponent("b").path, withDestinationPath: "a")
        XCTAssertThrowsError(try FileSystemResolver(maxHops: 8).resolve(SandboxPath(base.path + "/a/f")))
    }
}
