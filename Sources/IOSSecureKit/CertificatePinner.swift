import Foundation
import CryptoKit
#if canImport(Security)
import Security
#endif

/// SSL pinning via SHA-256 of the server certificate's Subject Public Key
/// Info (SPKI), not the leaf certificate's raw bytes.
///
/// **Why SPKI hash and not leaf-cert pinning**: pinning the leaf
/// certificate's hash ties the app to one specific certificate, which
/// typically rotates every 60-90 days (Let's Encrypt, and increasingly most
/// CAs). Every rotation would hard-break the app for anyone who hasn't
/// updated it yet — a self-inflicted outage on a schedule. The SPKI
/// (the public key itself, inside the cert) usually survives a renewal
/// issued from the same key pair, and even when it doesn't, you can pin the
/// *next* key ahead of a planned rotation and ship that before rotating,
/// which isn't possible with leaf pinning. This is the same tradeoff OWASP's
/// certificate/public-key pinning guidance and Chromium's (now-retired) HPKP
/// spec both landed on: pin the public key, not the certificate.
public final class CertificatePinner: NSObject, URLSessionDelegate {
    /// Base64-encoded SHA-256 hashes of the pinned SPKI(s). More than one
    /// allowed so a new key can be added ahead of a planned rotation
    /// (pin both the current and the next key, drop the old one once
    /// rotated).
    private let pinnedSPKIHashes: Set<String>
    private let enforce: Bool

    /// - Parameters:
    ///   - pinnedSPKIHashes: base64 SHA-256 digests of the DER-encoded SPKI.
    ///   - enforce: when `false`, mismatches are logged but not rejected.
    ///     Useful for a first rollout where you want telemetry before
    ///     cutting traffic off; defaults to `true` (fail closed).
    public init(pinnedSPKIHashes: Set<String>, enforce: Bool = true) {
        self.pinnedSPKIHashes = pinnedSPKIHashes
        self.enforce = enforce
    }

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        guard let serverCertificates = (SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate]),
              let leaf = serverCertificates.first else {
            completionHandler(enforce ? .cancelAuthenticationChallenge : .performDefaultHandling, nil)
            return
        }

        guard let spkiHash = Self.spkiSHA256Base64(for: leaf) else {
            completionHandler(enforce ? .cancelAuthenticationChallenge : .performDefaultHandling, nil)
            return
        }

        if pinnedSPKIHashes.contains(spkiHash) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(enforce ? .cancelAuthenticationChallenge : .performDefaultHandling, nil)
        }
    }

    /// Computes the base64 SHA-256 of a certificate's SPKI (not the whole
    /// certificate). Exposed `static` + `public` so callers can print the
    /// hash of a currently-served certificate while provisioning a new pin
    /// (e.g. a small CLI/debug build that connects once and logs this).
    public static func spkiSHA256Base64(for certificate: SecCertificate) -> String? {
        guard let publicKey = SecCertificateCopyKey(certificate),
              let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }
        // SecKeyCopyExternalRepresentation returns the raw key data without
        // the ASN.1 SPKI header. Re-wrap it so the hash matches the
        // conventional "hash of the DER SPKI" that `openssl x509 -pubkey |
        // openssl pkey -pubin -outform der | openssl dgst -sha256` produces,
        // which is what most pinning tooling/documentation expects.
        guard let algorithm = SecKeyCopyAttributes(publicKey) as? [CFString: Any],
              let keyType = algorithm[kSecAttrKeyType] as? String else {
            let digest = SHA256.hash(data: publicKeyData)
            return Data(digest).base64EncodedString()
        }
        let header = asn1Header(forKeyType: keyType, keySizeInBits: (algorithm[kSecAttrKeySizeInBits] as? Int) ?? 0)
        let spki = header + publicKeyData
        let digest = SHA256.hash(data: spki)
        return Data(digest).base64EncodedString()
    }

    /// Minimal ASN.1 SPKI headers for the key types we expect from a
    /// standard TLS server certificate (RSA-2048, RSA-4096, EC P-256). Not
    /// an exhaustive ASN.1 encoder — just enough to reconstruct the standard
    /// headers OpenSSL would emit for these specific, common cases.
    private static func asn1Header(forKeyType keyType: String, keySizeInBits: Int) -> Data {
        let rsa2048Header: [UInt8] = [
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
        ]
        let rsa4096Header: [UInt8] = [
            0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00
        ]
        let ecP256Header: [UInt8] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
            0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
            0x42, 0x00
        ]
        if keyType as String == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            return Data(ecP256Header)
        }
        return keySizeInBits > 2048 ? Data(rsa4096Header) : Data(rsa2048Header)
    }
}
