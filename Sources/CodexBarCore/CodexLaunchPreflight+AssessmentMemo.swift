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
    /// a content write, `chmod`, or xattr change (quarantine included) always yields a new key. The lifetime
    /// bounds how long a certificate revoked in place can go unnoticed.
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
        /// `isDefinitive` accepts are kept; timeouts, launch failures, and `spctl` errors stay retryable.
        /// Directories (app bundles) are never memoized.
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
            self.lock.withLock {
                self.entries = self.entries.filter { now < $0.value.expiresAt }
                if let result, isDefinitive(result) {
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
        let device: dev_t
        let inode: ino_t
        let size: off_t
        let modifiedSeconds: Int
        let modifiedNanoseconds: Int
        let changedSeconds: Int
        let changedNanoseconds: Int

        init?(path: String) {
            // `stat` follows symlinks, so a repointed `current` link or shim resolves to a new identity.
            var info = stat()
            guard stat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG else { return nil }
            self.path = path
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
