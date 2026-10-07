import Foundation
import Alamofire
#if canImport(Security)
import Security
#endif

/// Alamofire `ServerTrustEvaluating` adapter around the same SPKI SHA-256
/// pinning logic `CertificatePinner` uses for a plain `URLSession`.
///
/// `CertificatePinner` itself is a `URLSessionDelegate` (the shape the task
/// specifically asked for, and the natural fit if you're not using
/// Alamofire). Alamofire's `Session`, however, evaluates server trust
/// through its own internal `SessionDelegate` and a `ServerTrustManager` —
/// it doesn't take an arbitrary external `URLSessionDelegate` for trust
/// evaluation. Rather than fork the pinning logic, this type implements
/// `ServerTrustEvaluating` and defers the actual hash comparison to
/// `CertificatePinner.spkiSHA256Base64`, so both call sites (`URLSession`
/// consumers and Alamofire's `ServerTrustManager`) pin against the exact
/// same digest, computed the exact same way.
public enum SPKIPinningError: Error {
    case noCertificatesFound
    case spkiHashMismatch
}

public final class SPKIPinningTrustEvaluator: ServerTrustEvaluating {
    private let pinnedSPKIHashes: Set<String>

    public init(pinnedSPKIHashes: Set<String>) {
        self.pinnedSPKIHashes = pinnedSPKIHashes
    }

    public func evaluate(_ trust: SecTrust, forHost host: String) throws {
        guard let certificates = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = certificates.first else {
            throw AFError.serverTrustEvaluationFailed(reason: .trustEvaluationFailed(error: SPKIPinningError.noCertificatesFound))
        }
        guard let spkiHash = CertificatePinner.spkiSHA256Base64(for: leaf),
              pinnedSPKIHashes.contains(spkiHash) else {
            throw AFError.serverTrustEvaluationFailed(reason: .trustEvaluationFailed(error: SPKIPinningError.spkiHashMismatch))
        }
    }
}

public extension ServerTrustManager {
    /// Convenience factory: one evaluator, shared across every pinned host.
    /// Appropriate when every host this `Session` talks to should be
    /// pinned to the same set of SPKI hashes (true for naira-bank-ios,
    /// which only ever talks to the two sonofnos Render deployments).
    static func sonofnosPinned(hosts: [String], spkiHashes: Set<String>) -> ServerTrustManager {
        let evaluator = SPKIPinningTrustEvaluator(pinnedSPKIHashes: spkiHashes)
        var evaluators: [String: ServerTrustEvaluating] = [:]
        for host in hosts { evaluators[host] = evaluator }
        return ServerTrustManager(evaluators: evaluators)
    }
}
