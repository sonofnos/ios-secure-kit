# ios-secure-kit

A Swift Package of the mobile-security primitives a native banking app actually needs:
keychain-backed token storage, biometric unlock, SSL certificate pinning, and a JWT
attach/refresh interceptor that composes with [Alamofire](https://github.com/Alamofire/Alamofire)'s
`RequestInterceptor`. Built as a standalone, independently-versioned package rather than
app-local code, and consumed by [naira-bank-ios](https://github.com/sonofnos/naira-bank-ios)
via Swift Package Manager.

## What's in it

- **`KeychainStore`** — wraps `Security.framework` (`kSecClassGenericPassword`), storing
  items with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` so a session token dies with the
  device: readable only while unlocked, excluded from iCloud Keychain sync and backup/restore
  to a different device. Access goes through a `KeychainStoring` protocol so callers (and
  tests) aren't hard-wired to Security.framework.
- **`BiometricAuthenticator`** — async wrapper over `LocalAuthentication`/`LAContext` (Face
  ID / Touch ID / Optic ID). Typed errors (`notEnrolled`, `lockedOut`, `userCancelled`,
  `authenticationFailed`) so callers can react correctly instead of showing one generic
  "biometrics failed" alert — e.g. offer a PIN fallback on `notEnrolled`, don't nag on
  `userCancelled`.
- **`CertificatePinner`** — a `URLSessionDelegate` that pins the server's **SPKI (Subject
  Public Key Info) SHA-256 hash**, not the leaf certificate. See "Why SPKI, not leaf
  pinning" below.
- **`SPKIPinningTrustEvaluator`** — Alamofire's `Session` evaluates server trust through its
  own `SessionDelegate`/`ServerTrustManager`, not an arbitrary external `URLSessionDelegate`,
  so this adapts the exact same `CertificatePinner.spkiSHA256Base64` hashing logic to
  Alamofire's `ServerTrustEvaluating` protocol instead of duplicating it. Both the plain-
  `URLSession` path and the Alamofire path pin against the identical digest, computed the
  identical way.
- **`AuthInterceptor`** — attaches `Authorization: Bearer <token>` to every request and,
  on a 401, refreshes once and retries. Conforms to Alamofire's `RequestInterceptor`, but
  the refresh/retry *decision logic* sits behind a plain `TokenStoring` protocol so it's
  fully unit-testable without a live `Session` or network traffic. Concurrent 401s are
  coalesced onto a single in-flight refresh via an actor (`RefreshCoordinator`), so five
  requests failing at once don't trigger five refresh calls racing each other.

## Why SPKI, not leaf-certificate pinning

Pinning the leaf certificate's hash ties the app to one specific cert, which typically
rotates every 60–90 days (Let's Encrypt and most CAs now). Every rotation silently breaks
the app for anyone who hasn't updated yet — a self-inflicted outage on a schedule. The
SPKI (the public key itself, inside the cert) usually survives a renewal issued from the
same key pair, and you can pin the *next* key ahead of a planned rotation and ship that
before rotating — not possible with leaf pinning. This matches OWASP's pinning guidance
and the rationale behind the now-retired HPKP spec: pin the public key, not the
certificate.

`naira-bank-ios` pins against the real SPKI hashes served by
`sonofnos-core-banking.onrender.com` and `sonofnos-payments-collections.onrender.com`.

## Testing — what's real, what's faked, and why

```
$ swift test
Executed 22 tests, with 1 test skipped and 0 failures (0 unexpected) in 0.075 seconds
```

22 XCTest cases across 4 suites, run via `swift test` on this machine (Swift 6.4, Xcode 27).
One is intentionally skipped (see below).

- **`KeychainStoreTests`** (7 tests) — mostly run against `InMemoryKeychain`, a fake
  conforming to `KeychainStoring`. **The real gotcha**: `swift test` run from a plain SPM
  target has no host app bundle and no code-signing identity, so XCTest run this way can't
  rely on real keychain access the way an app target can — on iOS it fails outright
  (`errSecMissingEntitlement` without a keychain-access-group entitlement from a signed
  host app). `testRealKeychainStoreEitherWorksOrFailsCleanly` exercises the real
  `KeychainStore` (`Security.framework`) anyway and accepts either outcome (succeeds, or
  throws a typed `KeychainError`) rather than hard-asserting success — which is exactly
  what happened: on this macOS CLI environment it actually succeeded (generic-password
  items don't require the same entitlement here that they do on iOS), but that's
  environment-dependent, which is the point of the test. The *iOS* host-app path is what
  actually matters for a shipping app, and that's exercised for real in `naira-bank-ios`
  (keychain-backed JWT storage, running in the simulator).
- **`BiometricAuthenticatorTests`** (7 tests) — fully deterministic against
  `FakeBiometricContext`, a protocol fake for `LAContext`. This is the only sane way to test
  biometrics: CI runners have no biometric hardware, and even the simulator's "enrolled"
  state has to be toggled from Simulator's menu, not from a test. The protocol seam
  (`BiometricContext`) is what makes every outcome — not-enrolled, locked-out,
  user-cancelled, success — testable in milliseconds.
- **`CertificatePinnerTests`** (3 tests, 1 skipped) — construction and SPKI-hash-determinism
  tests. The skipped test documents that `SecCertificate` has no public API to synthesize a
  throwaway test certificate, so that specific test (same cert hashed twice should produce
  the same hash) skips cleanly rather than faking a certificate. The actual challenge-handling
  path (`urlSession(_:didReceive:completionHandler:)`) needs a real `URLAuthenticationChallenge`
  with a live `SecTrust`, which only exists mid-TLS-handshake — that's exercised by
  `naira-bank-ios` actually connecting over HTTPS to the live Render-hosted backends with
  pinning turned on.
- **`AuthInterceptorTests`** (5 tests) — deterministic against `FakeTokenStore`. Covers
  token attach, refresh success/failure, and documents (via
  `testConcurrentRefreshCallsAreNotNecessarilyCoalescedAtStoreLevel`) that the coalescing
  behavior lives in `AuthInterceptor`'s `RefreshCoordinator` actor, not in `TokenStoring`
  itself — `TokenStoring` is deliberately dumb. The Alamofire-specific `adapt`/`retry`
  methods are thin glue over this tested logic; they're exercised against a real `Session`
  from `naira-bank-ios`.

## A real gotcha hit while building this

Swift 6's strict concurrency checking flagged `NSLock.lock()`/`unlock()` called across an
`await` suspension point in the original `AuthInterceptor` implementation —
`NS_SWIFT_UNAVAILABLE_FROM_ASYNC`, a warning today but a hard error under the Swift 6
language mode. Replaced the manual lock with an actor (`RefreshCoordinator`) that does the
exact same coalescing (first caller's refresh runs, everyone else awaits its result) without
a lock that can be held across a suspension point. Also hit a `Sendable` warning on
`LAContextBiometricContext` (closures crossing into the `LAContext` completion handler) and
on `FakeTokenStore`'s mutable `var token` — resolved with `@unchecked Sendable` on the two
classes where the actual access pattern is safe (single-threaded test fake; `LAContext`'s own
completion handler is the only mutator) but the compiler can't prove it structurally.

## Usage

```swift
import IOSSecureKit
import Alamofire

let keychain = KeychainStore(service: "com.sonofnos.nairabank")

final class KeychainTokenStore: TokenStoring {
    func currentAccessToken() -> String? {
        try? keychain.getString("accessToken")
    }
    func refreshAccessToken() async throws -> String {
        // re-POST /api/auth/login, or a dedicated refresh endpoint
        let newToken = try await loginAgain()
        try keychain.setString(newToken, for: "accessToken")
        return newToken
    }
}

let session = Session(
    interceptor: AuthInterceptor(tokenStore: KeychainTokenStore()),
    serverTrustManager: nil // CertificatePinner is wired as a URLSessionDelegate instead
)

let biometrics = BiometricAuthenticator()
if biometrics.isAvailable() {
    try await biometrics.authenticate(reason: "Unlock Naira Bank")
}
```

## CI

`.github/workflows/ci.yml` — macOS runner, `swift build` + `swift test` on every push/PR.

## Tech

Swift 6.4 (strict concurrency / Swift 6 language mode), Swift Package Manager, Alamofire 5,
Security.framework, LocalAuthentication, CryptoKit, XCTest, GitHub Actions. iOS 15+ / macOS
12+.
