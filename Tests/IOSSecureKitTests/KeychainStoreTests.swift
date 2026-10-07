import XCTest
@testable import IOSSecureKit

final class KeychainStoreTests: XCTestCase {
    func testSetAndGetRoundTrips() throws {
        let keychain = InMemoryKeychain()
        try keychain.setString("abc.jwt.token", for: "accessToken")
        XCTAssertEqual(try keychain.getString("accessToken"), "abc.jwt.token")
    }

    func testGetMissingKeyReturnsNil() throws {
        let keychain = InMemoryKeychain()
        XCTAssertNil(try keychain.get("doesNotExist"))
    }

    func testSetOverwritesExistingValue() throws {
        let keychain = InMemoryKeychain()
        try keychain.setString("first", for: "k")
        try keychain.setString("second", for: "k")
        XCTAssertEqual(try keychain.getString("k"), "second")
    }

    func testDeleteRemovesValue() throws {
        let keychain = InMemoryKeychain()
        try keychain.setString("value", for: "k")
        try keychain.delete("k")
        XCTAssertNil(try keychain.get("k"))
    }

    func testDeleteOnMissingKeyDoesNotThrow() {
        let keychain = InMemoryKeychain()
        XCTAssertNoThrow(try keychain.delete("neverSet"))
    }

    func testStringRoundTripPreservesUnicode() throws {
        let keychain = InMemoryKeychain()
        let value = "token-with-emoji-\u{1F512}"
        try keychain.setString(value, for: "k")
        XCTAssertEqual(try keychain.getString("k"), value)
    }

    /// Real Security.framework-backed store. This exercises the actual
    /// `SecItemAdd`/`SecItemCopyMatching` code path. On a plain `swift test`
    /// run (no host app, no keychain-access-group entitlement) this is
    /// expected to fail with `errSecMissingEntitlement` or similar on some
    /// OS/toolchain combinations — that's the real gotcha documented in the
    /// README, not a bug in this test. We assert it either succeeds (when
    /// the environment allows it) or fails with a `KeychainError`, never
    /// crashes or hangs.
    func testRealKeychainStoreEitherWorksOrFailsCleanly() {
        let store = KeychainStore(service: "com.sonofnos.iossecurekit.tests")
        let key = "real-keychain-smoke-test"
        do {
            try store.set(Data("value".utf8), for: key)
            let readBack = try store.get(key)
            XCTAssertEqual(readBack, Data("value".utf8))
            try store.delete(key)
        } catch is KeychainError {
            // Expected in a sandboxed SPM test environment without
            // keychain entitlements. See README "Gotchas" section.
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }
}
