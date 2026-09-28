import Foundation

#if os(macOS)
extension CodexLaunchPreflight {
    /// Remembers Gatekeeper verdicts for standalone Mach-O launch candidates.
    ///
    /// `spctl --assess` re-hashes the whole binary on every call and nothing upstream caches a
    /// `rejected (… does not seem to be an app)` verdict, so each Codex lookup cost seconds of `syspolicyd`
    /// CPU and the total scaled with refresh cadence (#4078).
    ///
    /// A verdict is bound to a file, not to a path. The memo resolves the candidate to its device and inode
    /// and has Gatekeeper assess `/.vol/<device>/<inode>`, which names that file directly, so no symlink or
    /// directory swapped while `spctl` runs can change what was assessed. A single-file executable carries its
    /// own signature, so unlike an app bundle (see `KeychainAccessPreflight.ValidationMemo`) its identity
    /// covers everything the assessment read: device, inode, size, mtime and ctime. User space cannot set
    /// ctime, so a content write, `chmod`, or xattr change (quarantine included) is always a new identity.
    /// A verdict is kept only if the file's identity is unchanged when `spctl` returns, and a caller receives
    /// it only while its own path still names that file; otherwise the caller gets a fresh, unshared
    /// assessment of its path. The lifetime bounds how long a certificate revoked in place, with the file
    /// untouched, can go unnoticed. Where `/.vol` cannot reach the file, nothing is memoized.
    final class AssessmentMemo: @unchecked Sendable {
        static let shared = AssessmentMemo()
        static let capacity = 16
        static let lifetime: TimeInterval = 5 * 60

        /// Assessments are synchronous. Each pending file has its own result promise, so waiting callers
        /// share even a transient result without holding the dictionary lock or blocking unrelated files.
        /// `bound` records whether the file was unchanged when `spctl` returned.
        private final class Flight {
            private let condition = NSCondition()
            private var completed = false
            private var result: (assessment: GatekeeperAssessment?, bound: Bool) = (nil, false)

            func wait() -> (assessment: GatekeeperAssessment?, bound: Bool) {
                self.condition.lock()
                defer { self.condition.unlock() }
                while !self.completed {
                    self.condition.wait()
                }
                return self.result
            }

            func complete(_ assessment: GatekeeperAssessment?, bound: Bool) {
                self.condition.lock()
                self.result = (assessment, bound)
                self.completed = true
                self.condition.broadcast()
                self.condition.unlock()
            }
        }

        private let lock = NSLock()
        private var entries: [FileIdentity: (assessment: GatekeeperAssessment, expiresAt: TimeInterval)] = [:]
        private var flights: [FileIdentity: Flight] = [:]
        private let onJoin: @Sendable () -> Void
        private let onCacheHit: @Sendable () -> Void

        init(onJoin: @escaping @Sendable () -> Void = {}, onCacheHit: @escaping @Sendable () -> Void = {}) {
            self.onJoin = onJoin
            self.onCacheHit = onCacheHit
        }

        /// Returns the remembered verdict for the unchanged regular file `path` names, or assesses it. Only
        /// verdicts `isDefinitive` accepts are kept; timeouts, launch failures, and `spctl` errors stay
        /// retryable. Directories (app bundles) are never memoized. Verdicts are reported for `path`.
        func assessment(
            path: String,
            now: TimeInterval = ProcessInfo.processInfo.systemUptime,
            isDefinitive: (GatekeeperAssessment) -> Bool,
            assess: (String) -> GatekeeperAssessment?) -> GatekeeperAssessment?
        {
            guard let file = FileIdentity(path: path), file.isRegularFile,
                  FileIdentity(path: file.volumePath) == file
            else { return assess(path) }
            self.lock.lock()
            if let entry = self.entries[file], now < entry.expiresAt {
                self.lock.unlock()
                self.onCacheHit()
                return Self.deliver(entry.assessment, bound: true, file: file, path: path, assess: assess)
            }
            if let flight = self.flights[file] {
                self.lock.unlock()
                self.onJoin()
                let shared = flight.wait()
                return Self.deliver(shared.assessment, bound: shared.bound, file: file, path: path, assess: assess)
            }
            let flight = Flight()
            self.flights[file] = flight
            self.lock.unlock()

            let result = assess(file.volumePath)
            // Kept only if the file did not change while `spctl` read it.
            let bound = FileIdentity(path: file.volumePath) == file
            self.lock.withLock {
                self.entries = self.entries.filter { now < $0.value.expiresAt }
                if let result, bound, let reported = Self.attributed(result, from: file.volumePath, to: path),
                   isDefinitive(reported)
                {
                    if self.entries.count >= Self.capacity,
                       let firstToExpire = self.entries.min(by: { $0.value.expiresAt < $1.value.expiresAt })?.key
                    {
                        self.entries.removeValue(forKey: firstToExpire)
                    }
                    self.entries[file] = (result, now + Self.lifetime)
                }
                flight.complete(result, bound: bound)
                self.flights.removeValue(forKey: file)
            }
            return Self.deliver(result, bound: bound, file: file, path: path, assess: assess)
        }

        /// Every answer (cache hit, shared, or fresh) is checked against what the caller's path names
        /// immediately before it is returned. A verdict for a file the path no longer names is not an answer
        /// for this lookup, so the caller gets a fresh, unshared assessment of its path instead.
        private static func deliver(
            _ assessment: GatekeeperAssessment?,
            bound: Bool,
            file: FileIdentity,
            path: String,
            assess: (String) -> GatekeeperAssessment?) -> GatekeeperAssessment?
        {
            guard bound, FileIdentity(path: path) == file else { return assess(path) }
            return self.attributed(assessment, from: file.volumePath, to: path)
        }

        /// `spctl` names the path it was given at the start of its first line; report the caller's path.
        private static func attributed(
            _ assessment: GatekeeperAssessment?,
            from source: String,
            to path: String) -> GatekeeperAssessment?
        {
            guard let assessment, assessment.output.hasPrefix("\(source):") else { return assessment }
            return GatekeeperAssessment(
                output: path + String(assessment.output.dropFirst(source.count)),
                exitStatus: assessment.exitStatus)
        }
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

        /// Names this file without traversing any directory or symlink.
        var volumePath: String {
            "/.vol/\(self.device)/\(self.inode)"
        }

        /// `stat`, so a symlinked candidate resolves to the file it names right now.
        init?(path: String) {
            var info = stat()
            guard stat(path, &info) == 0 else { return nil }
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
