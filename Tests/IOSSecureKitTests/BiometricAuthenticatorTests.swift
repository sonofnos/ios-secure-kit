import XCTest
@testable import IOSSecureKit

final class BiometricAuthenticatorTests: XCTestCase {
    func testIsAvailableReflectsContext() {
        let fake = FakeBiometricContext(availability: (true, nil))
        let authenticator = BiometricAuthenticator(context: fake)
        XCTAssertTrue(authenticator.isAvailable())
    }

    func testIsAvailableFalseWhenNotEnrolled() {
        let fake = FakeBiometricContext(availability: (false, .notEnrolled))
        let authenticator = BiometricAuthenticator(context: fake)
        XCTAssertFalse(authenticator.isAvailable())
    }

    func testBiometryKindPassesThrough() {
        let fake = FakeBiometricContext(kind: .faceID)
        let authenticator = BiometricAuthenticator(context: fake)
        XCTAssertEqual(authenticator.biometryKind(), .faceID)
    }

    func testAuthenticateSucceeds() async throws {
        let fake = FakeBiometricContext(availability: (true, nil), evaluationResult: .success(()))
        let authenticator = BiometricAuthenticator(context: fake)
        try await authenticator.authenticate(reason: "Unlock your account")
    }

    func testAuthenticateThrowsWhenNotAvailable() async {
        let fake = FakeBiometricContext(availability: (false, .notEnrolled))
        let authenticator = BiometricAuthenticator(context: fake)
        do {
            try await authenticator.authenticate(reason: "Unlock")
            XCTFail("Expected to throw")
        } catch let error as BiometricAuthError {
            XCTAssertEqual(error, .notEnrolled)
        } catch {
            XCTFail("Wrong error type: \(error)")
        }
    }

    func testAuthenticateThrowsLockedOut() async {
        let fake = FakeBiometricContext(availability: (true, nil), evaluationResult: .failure(.lockedOut))
        let authenticator = BiometricAuthenticator(context: fake)
        do {
            try await authenticator.authenticate(reason: "Unlock")
            XCTFail("Expected to throw")
        } catch let error as BiometricAuthError {
            XCTAssertEqual(error, .lockedOut)
        } catch {
            XCTFail("Wrong error type: \(error)")
        }
    }

    func testAuthenticateThrowsUserCancelled() async {
        let fake = FakeBiometricContext(availability: (true, nil), evaluationResult: .failure(.userCancelled))
        let authenticator = BiometricAuthenticator(context: fake)
        do {
            try await authenticator.authenticate(reason: "Unlock")
            XCTFail("Expected to throw")
        } catch let error as BiometricAuthError {
            XCTAssertEqual(error, .userCancelled)
        } catch {
            XCTFail("Wrong error type: \(error)")
        }
    }
}
