import Foundation
import Testing
@testable import CodexBarCore

#if os(macOS)
struct CodexLaunchPreflightAssessmentMemoTests {
    private typealias Memo = CodexLaunchPreflight.AssessmentMemo
    private typealias Assessment = CodexLaunchPreflight.GatekeeperAssessment

    private static let notAnApp = "rejected (the code is valid but does not seem to be an app)\n" +
        "origin=Developer ID Application: Synthetic Fixture (FIXTURE01)"

    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var value = 0
        var count: Int {
            self.lock.withLock { self.value }
        }

        func increment() {
            self.lock.withLock { self.value += 1 }
        }
    }

    private struct Fixture {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)

        init() throws {
            try FileManager.default.createDirectory(at: self.root, withIntermediateDirectories: true)
        }

        func executable(_ name: String, contents: String = "synthetic native codex") throws -> URL {
            let url = self.root.appendingPathComponent(name)
            try Data(contents.utf8).write(to: url)
            return url
        }

        func remove() { try? FileManager.default.removeItem(at: self.root) }
    }

    private static func assess(
        _ memo: Memo,
        _ path: String,
        now: TimeInterval = 0,
        calls: Counter,
        output: String? = Self.notAnApp) -> Assessment?
    {
        memo.assessment(
            path: path,
            now: now,
            isDefinitive: { CodexLaunchPreflight.isDefinitiveAssessment($0.output, path: path) },
            assess: { _ in
                calls.increment()
                return output.map { Assessment(output: "\(path): \($0)", exitStatus: 3) }
            })
    }

    @Test
    func `an unchanged executable is assessed once`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let codex = try fixture.executable("codex")
        let memo = Memo()
        let calls = Counter()

        for _ in 0..<100 {
            #expect(Self.assess(memo, codex.path, calls: calls)?.exitStatus == 3)
        }

        #expect(calls.count == 1)
        print("assessment memo serial: requests=100 assessments=\(calls.count)")
    }

    @Test
    func `rewriting the executable forces a fresh assessment`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let codex = try fixture.executable("codex")
        let memo = Memo()
        let calls = Counter()
        _ = Self.assess(memo, codex.path, calls: calls)

        try Data("a codex update that is definitely not the old one".utf8).write(to: codex)
        _ = Self.assess(memo, codex.path, calls: calls)

        #expect(calls.count == 2)
    }

    @Test
    func `an extended attribute change alone forces a fresh assessment`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let codex = try fixture.executable("codex")
        let memo = Memo()
        let calls = Counter()
        let modifiedBefore = try FileManager.default.attributesOfItem(atPath: codex.path)[.modificationDate] as? Date
        _ = Self.assess(memo, codex.path, calls: calls)

        // Quarantine arrives as an xattr: size and mtime stay put, only ctime moves.
        let value = Array("0081;00000000;Synthetic;".utf8)
        let status = setxattr(codex.path, "com.apple.quarantine", value, value.count, 0, 0)
        #expect(status == 0)
        let modifiedAfter = try FileManager.default.attributesOfItem(atPath: codex.path)[.modificationDate] as? Date
        #expect(modifiedBefore == modifiedAfter)
        _ = Self.assess(memo, codex.path, calls: calls)

        #expect(calls.count == 2)
    }

    @Test
    func `a repointed symlink gets its own verdict`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let old = try fixture.executable("codex-0.1", contents: "old release")
        let new = try fixture.executable("codex-0.2", contents: "new release")
        let link = fixture.root.appendingPathComponent("codex")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: old)
        let memo = Memo()
        let calls = Counter()
        _ = Self.assess(memo, link.path, calls: calls)

        try FileManager.default.removeItem(at: link)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: new)
        _ = Self.assess(memo, link.path, calls: calls)

        #expect(calls.count == 2)
    }

    @Test
    func `verdicts expire after the lifetime`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let codex = try fixture.executable("codex")
        let memo = Memo()
        let calls = Counter()

        _ = Self.assess(memo, codex.path, now: 0, calls: calls)
        _ = Self.assess(memo, codex.path, now: Memo.lifetime - 1, calls: calls)
        #expect(calls.count == 1)

        _ = Self.assess(memo, codex.path, now: Memo.lifetime, calls: calls)
        #expect(calls.count == 2)
    }

    @Test
    func `timeouts and spctl errors stay retryable`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let codex = try fixture.executable("codex")
        let memo = Memo()
        let timeouts = Counter()
        let errors = Counter()

        for _ in 0..<3 {
            #expect(Self.assess(memo, codex.path, calls: timeouts, output: nil) == nil)
            _ = Self.assess(memo, codex.path, calls: errors, output: "spctl: syspolicyd is unavailable")
        }

        #expect(timeouts.count == 3)
        #expect(errors.count == 3)
    }

    @Test
    func `app bundles are never memoized`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let bundle = fixture.root.appendingPathComponent("Codex.app")
        try FileManager.default.createDirectory(at: bundle, withIntermediateDirectories: true)
        let memo = Memo()
        let calls = Counter()

        for _ in 0..<3 {
            _ = Self.assess(memo, bundle.path, calls: calls, output: "accepted\nsource=Notarized Developer ID")
        }

        #expect(calls.count == 3)
    }

    @Test
    func `concurrent callers share one assessment`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let codex = try fixture.executable("codex")
        let joins = Counter()
        let memo = Memo(onJoin: { joins.increment() })
        let calls = Counter()
        let path = codex.path

        DispatchQueue.concurrentPerform(iterations: 20) { _ in
            _ = memo.assessment(
                path: path,
                isDefinitive: { _ in true },
                assess: { _ in
                    calls.increment()
                    Thread.sleep(forTimeInterval: 0.2)
                    return Assessment(output: Self.notAnApp, exitStatus: 3)
                })
        }

        #expect(calls.count == 1)
        #expect(joins.count <= 19)
        print("assessment memo concurrent: requests=20 assessments=\(calls.count) joined=\(joins.count)")
    }

    @Test
    func `capacity evicts the verdict closest to expiry`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let memo = Memo()
        let calls = Counter()
        let paths = try (0...Memo.capacity).map { try fixture.executable("codex-\($0)").path }

        for (offset, path) in paths.enumerated() {
            _ = Self.assess(memo, path, now: TimeInterval(offset), calls: calls)
        }
        _ = Self.assess(memo, paths[1], now: TimeInterval(paths.count), calls: calls)
        #expect(calls.count == paths.count)

        _ = Self.assess(memo, paths[0], now: TimeInterval(paths.count), calls: calls)
        #expect(calls.count == paths.count + 1)
    }

    @Test
    func `only accepted and rejected verdicts are definitive`() {
        let path = "/tools/bin/codex"
        #expect(CodexLaunchPreflight.isDefinitiveAssessment("\(path): \(Self.notAnApp)", path: path))
        #expect(CodexLaunchPreflight.isDefinitiveAssessment(
            "\(path): accepted\nsource=Notarized Developer ID",
            path: path))
        #expect(!CodexLaunchPreflight.isDefinitiveAssessment(
            "spctl: syspolicyd is unavailable",
            path: path))
        #expect(!CodexLaunchPreflight.isDefinitiveAssessment("", path: path))
    }
}
#endif
