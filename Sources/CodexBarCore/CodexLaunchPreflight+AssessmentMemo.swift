import Foundation

#if os(macOS)
extension CodexLaunchPreflight {
    /// Remembers Gatekeeper verdicts for standalone Mach-O launch candidates.
    ///
    /// `spctl --assess` re-hashes the whole binary on every call and nothing upstream caches a
    /// `rejected (… does not seem to be an app)` verdict, so each Codex lookup cost seconds of `syspolicyd`
    /// CPU and the total scaled with refresh cadence (#4078). A single-file executable carries its own
    /// signature, so unlike an app bundle (see `KeychainAccessPreflight.ValidationMemo`) its stat identity
    /// covers everything the assessment read. `ctime` is part of the key because user space cannot set it:
    /// a content write, `chmod`, or xattr change (quarantine included) always yields a new key. The key also
    /// records every symlink the path crosses, and a verdict is kept only when the key read after `spctl`
    /// returns matches the one read before, so a target swapped during the assessment (even one swapped
    /// back) is never remembered. The lifetime bounds how long a certificate revoked in place can go
    /// unnoticed.
    final class AssessmentMemo: @unchecked Sendable {
        static let shared = AssessmentMemo()
        static let capacity = 16
        static let lifetime: TimeInterval = 60 * 60

        /// Assessments are synchronous. Each pending key has its own result promise, so waiting callers
        /// share even a transient result without holding the dictionary lock or blocking unrelated keys.
        private final class Flight {
            private let condition = NSCondition()
            private var completed = false
            private var result: GatekeeperAssessment?

            func wait() -> GatekeeperAssessment? {
                self.condition.lock()
                defer { self.condition.unlock() }
                while !self.completed {
                    self.condition.wait()
                }
                return self.result
            }

            func complete(_ result: GatekeeperAssessment?) {
                self.condition.lock()
                self.result = result
                self.completed = true
                self.condition.broadcast()
                self.condition.unlock()
            }
        }

        private let lock = NSLock()
        private var entries: [AssessmentKey: (assessment: GatekeeperAssessment, expiresAt: TimeInterval)] = [:]
        private var flights: [AssessmentKey: Flight] = [:]
        private let onJoin: @Sendable () -> Void

        init(onJoin: @escaping @Sendable () -> Void = {}) {
            self.onJoin = onJoin
        }

        /// Returns the remembered verdict for an unchanged regular file, or runs `assess`. Only verdicts
        /// `isDefinitive` accepts are kept, and only when the path resolved to the same file through the same
        /// symlinks before and after the assessment; timeouts, launch failures, and `spctl` errors stay
        /// retryable. Directories (app bundles) are never memoized.
        func assessment(
            path: String,
            now: TimeInterval = ProcessInfo.processInfo.systemUptime,
            isDefinitive: (GatekeeperAssessment) -> Bool,
            assess: (String) -> GatekeeperAssessment?) -> GatekeeperAssessment?
        {
            guard let key = AssessmentKey(path: path) else { return assess(path) }
            self.lock.lock()
            if let entry = self.entries[key], now < entry.expiresAt {
                self.lock.unlock()
                return entry.assessment
            }
            if let flight = self.flights[key] {
                self.lock.unlock()
                self.onJoin()
                return flight.wait()
            }
            let flight = Flight()
            self.flights[key] = flight
            self.lock.unlock()

            let result = assess(path)
            // Bind the verdict to what was assessed: anything that moved while `spctl` ran is not remembered.
            let unchanged = AssessmentKey(path: path) == key
            self.lock.withLock {
                self.entries = self.entries.filter { now < $0.value.expiresAt }
                if let result, unchanged, isDefinitive(result) {
                    if self.entries.count >= Self.capacity,
                       let firstToExpire = self.entries.min(by: { $0.value.expiresAt < $1.value.expiresAt })?.key
                    {
                        self.entries.removeValue(forKey: firstToExpire)
                    }
                    self.entries[key] = (result, now + Self.lifetime)
                }
                flight.complete(result)
                self.flights.removeValue(forKey: key)
            }
            return result
        }
    }

    private struct AssessmentKey: Hashable {
        let path: String
        let resolvedPath: String
        let links: [LinkIdentity]
        let target: FileIdentity

        init?(path: String) {
            guard let resolution = Self.resolve(path),
                  let target = FileIdentity(path: resolution.path),
                  target.isRegularFile
            else { return nil }
            self.path = path
            self.resolvedPath = resolution.path
            self.links = resolution.links
            self.target = target
        }

        /// Resolves an absolute path like `realpath(3)`, recording each symlink crossed. A symlink cannot be
        /// retargeted in place: replacing it creates a new inode and renaming it moves its ctime, so the chain
        /// changes whenever any hop does, including a swap that is later reverted.
        private static func resolve(_ path: String) -> (path: String, links: [LinkIdentity])? {
            guard path.hasPrefix("/") else { return nil }
            var pending = path.split(separator: "/").map(String.init)
            var resolved: [String] = []
            var links: [LinkIdentity] = []
            while !pending.isEmpty {
                let component = pending.removeFirst()
                if component.isEmpty || component == "." { continue }
                if component == ".." {
                    _ = resolved.popLast()
                    continue
                }
                let candidate = "/" + (resolved + [component]).joined(separator: "/")
                guard let identity = FileIdentity(path: candidate) else { return nil }
                guard identity.isSymbolicLink else {
                    resolved.append(component)
                    continue
                }
                guard links.count < 32, let destination = Self.readLink(candidate) else { return nil }
                links.append(LinkIdentity(path: candidate, destination: destination, identity: identity))
                if destination.hasPrefix("/") {
                    resolved.removeAll()
                }
                pending = destination.split(separator: "/").map(String.init) + pending
            }
            return ("/" + resolved.joined(separator: "/"), links)
        }

        private static func readLink(_ path: String) -> String? {
            var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
            let count = readlink(path, &buffer, Int(PATH_MAX))
            guard count > 0 else { return nil }
            return String(bytes: buffer[..<count].map { UInt8(bitPattern: $0) }, encoding: .utf8)
        }
    }

    private struct LinkIdentity: Hashable {
        let path: String
        let destination: String
        let identity: FileIdentity
    }

    private struct FileIdentity: Hashable {
        let mode: mode_t
        let device: dev_t
        let inode: ino_t
        let size: off_t
        let modifiedSeconds: Int
        let modifiedNanoseconds: Int
        let changedSeconds: Int
        let changedNanoseconds: Int

        var isRegularFile: Bool {
            self.mode & S_IFMT == S_IFREG
        }

        var isSymbolicLink: Bool {
            self.mode & S_IFMT == S_IFLNK
        }

        /// `lstat`: a symlink is described as itself, never as its target.
        init?(path: String) {
            var info = stat()
            guard lstat(path, &info) == 0 else { return nil }
            self.mode = info.st_mode
            self.device = info.st_dev
            self.inode = info.st_ino
            self.size = info.st_size
            self.modifiedSeconds = info.st_mtimespec.tv_sec
            self.modifiedNanoseconds = info.st_mtimespec.tv_nsec
            self.changedSeconds = info.st_ctimespec.tv_sec
            self.changedNanoseconds = info.st_ctimespec.tv_nsec
        }
    }
}
#endif
