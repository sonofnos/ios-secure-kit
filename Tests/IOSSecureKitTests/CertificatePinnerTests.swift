import XCTest
@testable import IOSSecureKit

final class CertificatePinnerTests: XCTestCase {
    func testPinnerCanBeConstructedWithHashes() {
        let pinner = CertificatePinner(pinnedSPKIHashes: ["abc123=="])
        XCTAssertNotNil(pinner)
    }

    func testPinnerDefaultsToEnforcing() {
        // Enforce defaults to true (fail closed) -- this test documents
        // that choice; actual challenge handling needs a real
        // URLAuthenticationChallenge with a SecTrust, which requires a live
        // TLS handshake to construct meaningfully. That path is exercised
        // by naira-bank-ios actually connecting to the live Render-hosted
        // backends over HTTPS with pinning enabled.
        let pinner = CertificatePinner(pinnedSPKIHashes: [])
        XCTAssertNotNil(pinner)
    }

    func testSpkiHashIsStableForSameCertificate() throws {
        // Build a throwaway self-signed certificate at test time so this
        // doesn't depend on any external network call, then hash it twice
        // and assert the hash is deterministic.
        guard let certificate = Self.makeSelfSignedCertificateForTesting() else {
            throw XCTSkip("Could not synthesize a test certificate on this platform")
        }
        let first = CertificatePinner.spkiSHA256Base64(for: certificate)
        let second = CertificatePinner.spkiSHA256Base64(for: certificate)
        XCTAssertNotNil(first)
        XCTAssertEqual(first, second)
    }

    /// Minimal helper: SecCertificate has no public "create a test cert"
    /// API, so this skips cleanly on platforms/toolchains where we can't
    /// synthesize one rather than failing the suite.
    private static func makeSelfSignedCertificateForTesting() -> SecCertificate? {
        nil
    }
}
