import CryptoKit
import Foundation

/// Stores native Codex credentials. Switching deliberately leaves config.toml alone.
actor CodexAccountSnapshotService {
    static let shared = CodexAccountSnapshotService()
    private let fileManager = FileManager.default
    let codexDirectory: URL

    init(codexDirectory: URL? = nil) {
        self.codexDirectory = codexDirectory ?? FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".codex", isDirectory: true)
    }

    private var snapshotDirectory: URL { codexDirectory.appendingPathComponent("quotio-accounts") }
    private var authURL: URL { codexDirectory.appendingPathComponent("auth.json") }

    nonisolated struct Snapshot: Sendable {
        let accountKey: String
        let email: String?
        let accountID: String?
        let url: URL
    }

    enum SnapshotError: LocalizedError {
        case currentAuthMissing, snapshotMissing, invalidCredential, accountChanged
        var errorDescription: String? {
            switch self {
            case .currentAuthMissing: "codex.account.authMissing".localizedStatic()
            case .snapshotMissing: "codex.account.snapshotMissing".localizedStatic()
            case .invalidCredential: "codex.account.invalidCredential".localizedStatic()
            case .accountChanged: "codex.account.changed".localizedStatic()
            }
        }
    }

    nonisolated static func identity(in data: Data) -> (email: String?, accountID: String?)? {
        guard let auth = try? JSONDecoder().decode(CodexCLIAuthFile.self, from: data),
              let tokens = auth.tokens, tokens.accessToken?.isEmpty == false else { return nil }
        let email = MonitorIdentity.jwtString(tokens.idToken, claim: "email")
        let accountID = tokens.accountId ?? MonitorIdentity.jwtNestedString(
            tokens.idToken, namespace: "https://api.openai.com/auth", claim: "chatgpt_account_id")
        guard email != nil || accountID != nil else { return nil }
        return (email, accountID)
    }

    nonisolated static func sameAccount(_ first: Data, _ second: Data) -> Bool {
        guard let lhs = identity(in: first), let rhs = identity(in: second) else { return false }
        if let left = lhs.accountID, let right = rhs.accountID { return left == right }
        return lhs.email != nil && lhs.email == rhs.email
    }

    /// A CLI process or quota refresh may have rotated one copy since the account was saved.
    nonisolated static func mostRecentAuth(in candidates: [Data]) -> Data? {
        func timestamps(_ data: Data) -> (TimeInterval, TimeInterval) {
            guard let auth = try? JSONDecoder().decode(CodexCLIAuthFile.self, from: data) else { return (0, 0) }
            let refreshDate = auth.lastRefresh.flatMap { ISO8601DateFormatter().date(from: $0) }?.timeIntervalSince1970 ?? 0
            guard let token = auth.tokens?.accessToken,
                  let payload = token.split(separator: ".").dropFirst().first else { return (0, refreshDate) }
            var encoded = String(payload).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            encoded += String(repeating: "=", count: (4 - encoded.count % 4) % 4)
            let json = Data(base64Encoded: encoded).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            return (json?["exp"] as? TimeInterval ?? 0, refreshDate)
        }
        let valid = candidates.filter { identity(in: $0) != nil }
        guard let first = valid.first, valid.allSatisfy({ sameAccount(first, $0) }) else { return nil }
        return valid.max { timestamps($0) < timestamps($1) }
    }

    func currentAuthData() -> Data? { try? Data(contentsOf: authURL) }

    func snapshots() -> [Snapshot] {
        let files = (try? fileManager.contentsOfDirectory(at: snapshotDirectory,
            includingPropertiesForKeys: nil)) ?? []
        return files.filter { $0.lastPathComponent.hasSuffix(".auth.json") }.compactMap { url in
            guard let data = try? Data(contentsOf: url), let identity = Self.identity(in: data) else { return nil }
            let metadataURL = url.deletingPathExtension().appendingPathExtension("account-key")
            let key = (try? String(contentsOf: metadataURL, encoding: .utf8))
                ?? identity.email ?? identity.accountID
            guard let key, !key.isEmpty else { return nil }
            return Snapshot(accountKey: key, email: identity.email, accountID: identity.accountID, url: url)
        }.sorted { $0.accountKey < $1.accountKey }
    }

    func snapshotURL(for accountKey: String) -> URL? {
        let records = snapshots()
        if let exact = records.first(where: { $0.accountKey == accountKey }) { return exact.url }
        let matches = records.filter { $0.email == accountKey || $0.accountID == accountKey }
        return matches.count == 1 ? matches[0].url : nil
    }

    func snapshotAuthData(for accountKey: String) -> Data? {
        guard let url = snapshotURL(for: accountKey) else { return nil }
        return try? Data(contentsOf: url)
    }

    func save(_ data: Data, for accountKey: String) throws {
        guard Self.identity(in: data) != nil, !accountKey.isEmpty else { throw SnapshotError.invalidCredential }
        let stem = SHA256.hash(data: Data(accountKey.utf8)).map { String(format: "%02x", $0) }.joined()
        let url = snapshotDirectory.appendingPathComponent(stem + ".auth.json")
        try SecureAtomicFileWriter.write(Data(accountKey.utf8), to: url.deletingPathExtension().appendingPathExtension("account-key"))
        try SecureAtomicFileWriter.write(data, to: url)
    }

    func saveCurrent(for accountKey: String, expectedAuth: Data) throws {
        guard let data = currentAuthData() else { throw SnapshotError.currentAuthMissing }
        guard Self.sameAccount(data, expectedAuth) else { throw SnapshotError.accountChanged }
        try save(data, for: accountKey)
    }

    /// Validate first, preserve the outgoing account, then atomically replace only auth.json.
    func activate(_ data: Data, accountKey: String) throws {
        guard Self.identity(in: data) != nil,
              var json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw SnapshotError.invalidCredential
        }
        json["auth_mode"] = "chatgpt"
        json["OPENAI_API_KEY"] = NSNull()
        let nativeData = try JSONSerialization.data(withJSONObject: json, options: [.prettyPrinted, .sortedKeys])
        if fileManager.fileExists(atPath: authURL.path) {
            let current = try Data(contentsOf: authURL)
            let backup = codexDirectory.appendingPathComponent("auth.json.backup.\(UUID().uuidString)")
            try SecureAtomicFileWriter.write(current, to: backup)
            if let identity = Self.identity(in: current) {
                let existingKey = snapshots().first { snapshot in
                    guard let saved = try? Data(contentsOf: snapshot.url) else { return false }
                    return Self.sameAccount(current, saved)
                }?.accountKey
                var outgoingKey = existingKey ?? identity.email ?? identity.accountID!
                if let saved = snapshotAuthData(for: outgoingKey), !Self.sameAccount(current, saved) {
                    outgoingKey = identity.accountID ?? outgoingKey
                }
                try save(current, for: outgoingKey)
            }
        }
        try save(nativeData, for: accountKey)
        try SecureAtomicFileWriter.write(nativeData, to: authURL)
    }

    /// Update only copies of the exact credential that was refreshed, never a newly selected account.
    func persistRefresh(_ refreshed: CodexCLIQuotaFetcher.TokenRefresh, originalRefreshToken: String) throws {
        for url in Set(snapshots().map(\.url) + [authURL]) {
            guard let data = try? Data(contentsOf: url),
                  var json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  var tokens = json["tokens"] as? [String: Any],
                  tokens["refresh_token"] as? String == originalRefreshToken else { continue }
            tokens["access_token"] = refreshed.accessToken
            tokens["refresh_token"] = refreshed.refreshToken ?? originalRefreshToken
            if let idToken = refreshed.idToken { tokens["id_token"] = idToken }
            json["tokens"] = tokens
            json["last_refresh"] = ISO8601DateFormatter().string(from: Date())
            try SecureAtomicFileWriter.write(try JSONSerialization.data(withJSONObject: json, options: [.prettyPrinted, .sortedKeys]), to: url)
        }
    }
}
