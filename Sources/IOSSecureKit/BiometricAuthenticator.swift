import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

public enum BiometricAuthError: Error, Equatable {
    case notAvailable(reason: String)
    case notEnrolled
    case lockedOut
    case userCancelled
    case authenticationFailed
    case other(String)
}

public enum BiometricKind: Equatable {
    case none
    case touchID
    case faceID
    case opticID
}

/// Protocol seam over `LAContext` so unit tests can simulate every outcome
/// (success, not-enrolled, lockout, cancel) deterministically instead of
/// depending on the simulator's biometric enrollment state, which `swift
/// test` cannot control and real Face ID/Touch ID hardware obviously isn't
/// present for at all in CI.
public protocol BiometricContext {
    func canEvaluate(policy: LAPolicyKind) -> (Bool, BiometricAuthError?)
    func biometryKind() -> BiometricKind
    func evaluate(policy: LAPolicyKind, reason: String) async -> Result<Void, BiometricAuthError>
}

/// Mirrors the subset of `LAPolicy` this library cares about, without
/// forcing every platform target to import LocalAuthentication directly.
public enum LAPolicyKind {
    case deviceOwnerAuthenticationWithBiometrics
    case deviceOwnerAuthentication
}

#if canImport(LocalAuthentication)
/// Real `LAContext`-backed implementation.
public final class LAContextBiometricContext: BiometricContext, @unchecked Sendable {
    public init() {}

    public func canEvaluate(policy: LAPolicyKind) -> (Bool, BiometricAuthError?) {
        let context = LAContext()
        var error: NSError?
        let ok = context.canEvaluatePolicy(laPolicy(for: policy), error: &error)
        guard let error else { return (ok, nil) }
        return (ok, map(error))
    }

    public func biometryKind() -> BiometricKind {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch context.biometryType {
        case .faceID: return .faceID
        case .touchID: return .touchID
        case .opticID: return .opticID
        default: return .none
        }
    }

    public func evaluate(policy: LAPolicyKind, reason: String) async -> Result<Void, BiometricAuthError> {
        let context = LAContext()
        return await withCheckedContinuation { continuation in
            context.evaluatePolicy(laPolicy(for: policy), localizedReason: reason) { success, error in
                if success {
                    continuation.resume(returning: .success(()))
                } else if let error = error as NSError? {
                    continuation.resume(returning: .failure(self.map(error)))
                } else {
                    continuation.resume(returning: .failure(.authenticationFailed))
                }
            }
        }
    }

    private func laPolicy(for kind: LAPolicyKind) -> LAPolicy {
        switch kind {
        case .deviceOwnerAuthenticationWithBiometrics: return .deviceOwnerAuthenticationWithBiometrics
        case .deviceOwnerAuthentication: return .deviceOwnerAuthentication
        }
    }

    private func map(_ error: NSError) -> BiometricAuthError {
        guard let code = LAError.Code(rawValue: error.code) else {
            return .other(error.localizedDescription)
        }
        switch code {
        case .biometryNotAvailable, .biometryNotEnrolled:
            return .notEnrolled
        case .biometryLockout:
            return .lockedOut
        case .userCancel, .systemCancel, .appCancel:
            return .userCancelled
        case .authenticationFailed:
            return .authenticationFailed
        default:
            return .other(error.localizedDescription)
        }
    }
}
#endif

/// Async wrapper used by apps. Takes a `BiometricContext` so it can be
/// unit-tested with `FakeBiometricContext` below instead of real hardware.
public final class BiometricAuthenticator {
    private let context: BiometricContext

    #if canImport(LocalAuthentication)
    public convenience init() {
        self.init(context: LAContextBiometricContext())
    }
    #endif

    public init(context: BiometricContext) {
        self.context = context
    }

    /// Whether biometric auth is currently usable on this device (enrolled,
    /// not locked out). Check this before showing a "use Face ID" toggle.
    public func isAvailable() -> Bool {
        context.canEvaluate(policy: .deviceOwnerAuthenticationWithBiometrics).0
    }

    public func biometryKind() -> BiometricKind {
        context.biometryKind()
    }

    /// Prompts the user with the given reason. Returns normally on success,
    /// throws a typed `BiometricAuthError` otherwise so callers can
    /// distinguish "user tapped cancel" (don't nag) from "not enrolled"
    /// (offer a passcode/PIN fallback) from "locked out" (tell them to use
    /// Settings or wait).
    public func authenticate(reason: String) async throws {
        let (available, availabilityError) = context.canEvaluate(policy: .deviceOwnerAuthenticationWithBiometrics)
        if !available {
            throw availabilityError ?? .notAvailable(reason: "Biometric authentication is not available.")
        }
        let result = await context.evaluate(policy: .deviceOwnerAuthenticationWithBiometrics, reason: reason)
        switch result {
        case .success:
            return
        case .failure(let error):
            throw error
        }
    }
}

/// Deterministic fake for unit tests and SwiftUI previews.
public final class FakeBiometricContext: BiometricContext {
    public var availability: (Bool, BiometricAuthError?)
    public var kind: BiometricKind
    public var evaluationResult: Result<Void, BiometricAuthError>

    public init(
        availability: (Bool, BiometricAuthError?) = (true, nil),
        kind: BiometricKind = .faceID,
        evaluationResult: Result<Void, BiometricAuthError> = .success(())
    ) {
        self.availability = availability
        self.kind = kind
        self.evaluationResult = evaluationResult
    }

    public func canEvaluate(policy: LAPolicyKind) -> (Bool, BiometricAuthError?) {
        availability
    }

    public func biometryKind() -> BiometricKind {
        kind
    }

    public func evaluate(policy: LAPolicyKind, reason: String) async -> Result<Void, BiometricAuthError> {
        evaluationResult
    }
}
