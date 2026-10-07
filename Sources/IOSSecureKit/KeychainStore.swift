import Foundation
#if canImport(Security)
import Security
#endif

/// Abstraction over keychain-style secure storage so callers (and tests) can
/// swap in an in-memory fake without touching Security.framework.
///
/// This is the seam that makes `KeychainStore` unit-testable at all: XCTest
/// run from `swift test` on a plain SPM target has no host app bundle, no
/// keychain-access-group entitlement, and no code signing identity. Calling
/// into `SecItemAdd`/`SecItemCopyMatching` directly from that environment
/// fails unpredictably (`errSecMissingEntitlement` / `errSecNotAvailable`
/// depending on OS version) rather than behaving like a real app would.
/// Real apps link an entitled host target, so `KeychainStore` is still the
/// thing you ship — but tests exercise the protocol through `InMemoryKeychain`
/// instead of asserting on the real keychain.
public protocol KeychainStoring {
    func set(_ data: Data, for key: String) throws
    func get(_ key: String) throws -> Data?
    func delete(_ key: String) throws
}

public enum KeychainError: Error, Equatable {
    case unhandledStatus(OSStatus)
    case unexpectedData
}

/// Real Security.framework-backed keychain store.
///
/// Items are stored as `kSecClassGenericPassword` entries scoped to a caller
/// supplied `service` string, with
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — the item is readable only
/// while the device is unlocked, never leaves the device (excluded from
/// iCloud Keychain / backups), and does not survive a restore to a different
/// device. That's the right tradeoff for a session JWT: it should die with
/// the device, not migrate to a new phone via backup restore.
public final class KeychainStore: KeychainStoring {
    private let service: String
    private let accessibility: CFString

    public init(service: String, accessibility: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly) {
        self.service = service
        self.accessibility = accessibility
    }

    public func set(_ data: Data, for key: String) throws {
        var query = baseQuery(for: key)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = accessibility

        let addStatus = SecItemAdd(query as CFDictionary, nil)
        if addStatus == errSecSuccess {
            return
        }
        if addStatus == errSecDuplicateItem {
            let searchQuery = baseQuery(for: key)
            let attributesToUpdate: [String: Any] = [kSecValueData as String: data]
            let updateStatus = SecItemUpdate(searchQuery as CFDictionary, attributesToUpdate as CFDictionary)
            guard updateStatus == errSecSuccess else {
                throw KeychainError.unhandledStatus(updateStatus)
            }
            return
        }
        throw KeychainError.unhandledStatus(addStatus)
    }

    public func get(_ key: String) throws -> Data? {
        var query = baseQuery(for: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { throw KeychainError.unexpectedData }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.unhandledStatus(status)
        }
    }

    public func delete(_ key: String) throws {
        let query = baseQuery(for: key)
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unhandledStatus(status)
        }
    }

    private func baseQuery(for key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
    }
}

/// In-memory fake used by tests (and safe to use in SwiftUI previews / CI
/// unit tests that shouldn't touch the real keychain). Not thread-safe by
/// design simplicity — callers needing concurrent access should serialize
/// through an actor, same as they would for the real store.
public final class InMemoryKeychain: KeychainStoring {
    private var storage: [String: Data] = [:]

    public init() {}

    public func set(_ data: Data, for key: String) throws {
        storage[key] = data
    }

    public func get(_ key: String) throws -> Data? {
        storage[key]
    }

    public func delete(_ key: String) throws {
        storage.removeValue(forKey: key)
    }
}

/// Convenience string helpers layered on top of the `Data`-based protocol,
/// since most real use (JWTs, refresh tokens) is string data.
public extension KeychainStoring {
    func setString(_ value: String, for key: String) throws {
        guard let data = value.data(using: .utf8) else { throw KeychainError.unexpectedData }
        try set(data, for: key)
    }

    func getString(_ key: String) throws -> String? {
        guard let data = try get(key) else { return nil }
        guard let string = String(data: data, encoding: .utf8) else { throw KeychainError.unexpectedData }
        return string
    }
}
