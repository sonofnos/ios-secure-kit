import Foundation
import Alamofire

/// Framework-agnostic token source. `AuthInterceptor` only needs to read the
/// current access token and trigger a refresh — it doesn't know or care
/// whether that's backed by `KeychainStore`, a mock, or anything else. This
/// is what keeps the retry/refresh *logic* testable without Alamofire,
/// network calls, or a keychain in the loop at all.
public protocol TokenStoring: Sendable {
    func currentAccessToken() -> String?
    /// Performs a refresh (e.g. POST /api/auth/login again, or a dedicated
    /// refresh endpoint) and persists the new token. Returns the new token,
    /// or throws if refresh itself failed (e.g. refresh token also expired —
    /// caller should treat that as "log the user out").
    func refreshAccessToken() async throws -> String
}

public enum AuthInterceptorError: Error {
    case refreshFailed(Error)
    case noTokenAvailable
}

/// Attaches a bearer token to every outgoing request and, on a 401,
/// refreshes the token exactly once and retries the request with the new
/// one. Conforms to Alamofire's `RequestInterceptor` so it drops straight
/// into a `Session(interceptor:)` — the framework-specific glue is this one
/// file; `TokenStoring` and the retry decision logic above it are plain
/// Swift and unit-testable without Alamofire spinning up real requests.
///
/// Concurrency note: multiple requests can 401 at once (e.g. 5 parallel
/// account calls right as the token expires). Without coordination each one
/// would trigger its own refresh — wasteful, and racy against whichever
/// refresh response lands last. `refreshTask` coalesces concurrent retries
/// onto a single in-flight refresh `Task`, so only the first 401 actually
/// calls `refreshAccessToken()`; the rest await the same task and reuse its
/// result.
public final class AuthInterceptor: RequestInterceptor {
    private let tokenStore: TokenStoring
    private let refreshCoordinator = RefreshCoordinator()

    public init(tokenStore: TokenStoring) {
        self.tokenStore = tokenStore
    }

    public func adapt(_ urlRequest: URLRequest, for session: Session, completion: @escaping (Result<URLRequest, Error>) -> Void) {
        var request = urlRequest
        if let token = tokenStore.currentAccessToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        completion(.success(request))
    }

    public func retry(
        _ request: Request,
        for session: Session,
        dueTo error: Error,
        completion: @escaping (RetryResult) -> Void
    ) {
        guard let statusCode = request.response?.statusCode, statusCode == 401 else {
            completion(.doNotRetry)
            return
        }
        // Don't retry forever: Alamofire tracks retry count per request.
        guard request.retryCount < 1 else {
            completion(.doNotRetry)
            return
        }

        Task {
            do {
                _ = try await coalescedRefresh()
                completion(.retry)
            } catch {
                completion(.doNotRetryWithError(AuthInterceptorError.refreshFailed(error)))
            }
        }
    }

    /// Ensures only one refresh is in flight at a time; concurrent callers
    /// await the same `Task`.
    private func coalescedRefresh() async throws -> String {
        try await refreshCoordinator.refresh { [tokenStore] in
            try await tokenStore.refreshAccessToken()
        }
    }
}

/// Actor-isolated coalescing: Swift 6's strict concurrency mode flags
/// `NSLock` used across an `await` suspension point as unsafe (the lock
/// could be held across a thread hop). An actor is the async-safe
/// replacement -- same coalescing behavior (only the first caller's work
/// actually runs; everyone else awaits its result), expressed without a
/// manually-managed lock.
private actor RefreshCoordinator {
    private var inFlight: Task<String, Error>?

    func refresh(_ operation: @escaping () async throws -> String) async throws -> String {
        if let inFlight {
            return try await inFlight.value
        }
        let task = Task { try await operation() }
        inFlight = task
        defer { inFlight = nil }
        return try await task.value
    }
}

/// In-memory fake for unit tests: deterministic, no Alamofire `Session`
/// required to exercise refresh-coalescing or token-attach behavior.
public final class FakeTokenStore: TokenStoring, @unchecked Sendable {
    public var token: String?
    public var refreshCallCount = 0
    public var refreshResult: Result<String, Error>

    public init(token: String? = "initial-token", refreshResult: Result<String, Error> = .success("refreshed-token")) {
        self.token = token
        self.refreshResult = refreshResult
    }

    public func currentAccessToken() -> String? { token }

    public func refreshAccessToken() async throws -> String {
        refreshCallCount += 1
        switch refreshResult {
        case .success(let newToken):
            token = newToken
            return newToken
        case .failure(let error):
            throw error
        }
    }
}
