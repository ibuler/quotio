import XCTest
@testable import Quotio

final class CodexAccountSnapshotTests: XCTestCase {
    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("quotio-account-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func auth(_ id: String, email: String = "test@example.invalid", refresh: String? = nil) throws -> Data {
        let payload = try JSONSerialization.data(withJSONObject: ["email": email])
            .base64EncodedString().replacingOccurrences(of: "=", with: "")
        return try JSONSerialization.data(withJSONObject: [
            "auth_mode": "chatgpt", "custom_field": "preserved",
            "tokens": ["account_id": id, "id_token": "header.\(payload).signature",
                       "access_token": "fake-access-\(id)", "refresh_token": refresh ?? "fake-refresh-\(id)"]
        ])
    }

    func testRoundTripPreservesConfigAndBacksUpOutgoingCredentials() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let service = CodexAccountSnapshotService(codexDirectory: dir)
        let original = try auth("a", email: "a@example.invalid")
        let target = try auth("b", email: "b@example.invalid")
        let config = Data("model = \"keep-my-model\"\n".utf8)
        try original.write(to: dir.appendingPathComponent("auth.json"))
        try config.write(to: dir.appendingPathComponent("config.toml"))
        try await service.activate(target, accountKey: "b@example.invalid")
        let switched = try Data(contentsOf: dir.appendingPathComponent("auth.json"))
        XCTAssertTrue(CodexAccountSnapshotService.sameAccount(switched, target))
        XCTAssertEqual(try Data(contentsOf: dir.appendingPathComponent("config.toml")), config)
        let saved = await service.snapshotAuthData(for: "a@example.invalid")
        XCTAssertEqual(saved, original)
        try await service.activate(XCTUnwrap(saved), accountKey: "a@example.invalid")
        let current = await service.currentAuthData()
        XCTAssertTrue(CodexAccountSnapshotService.sameAccount(try XCTUnwrap(current), original))
        let backups = try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("auth.json.backup.") }
        XCTAssertEqual(backups.count, 2)
        XCTAssertTrue(try backups.map { try Data(contentsOf: $0) }.contains(original))
        for url in backups + [dir.appendingPathComponent("auth.json")] {
            let permissions = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
            XCTAssertEqual(permissions, 0o600)
        }
    }

    func testInvalidCredentialDoesNotTouchCurrentFiles() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let service = CodexAccountSnapshotService(codexDirectory: dir)
        let original = try auth("a")
        try original.write(to: dir.appendingPathComponent("auth.json"))
        do {
            try await service.activate(Data("{}".utf8), accountKey: "invalid")
            XCTFail("Invalid credentials should fail")
        } catch {}
        XCTAssertEqual(try Data(contentsOf: dir.appendingPathComponent("auth.json")), original)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path), ["auth.json"])
    }

    func testIdentityUsesAccountIDForSameEmailAccounts() throws {
        XCTAssertFalse(CodexAccountSnapshotService.sameAccount(try auth("personal"), try auth("team")))
        XCTAssertNil(CodexAccountSnapshotService.mostRecentAuth(in: [try auth("personal"), try auth("team")]))
    }

    func testSaveRejectsAccountChangedSinceUIWasLoaded() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let service = CodexAccountSnapshotService(codexDirectory: dir)
        try auth("b").write(to: dir.appendingPathComponent("auth.json"))
        do {
            try await service.saveCurrent(for: "a", expectedAuth: auth("a"))
            XCTFail("Must not label account B as account A")
        } catch CodexAccountSnapshotService.SnapshotError.accountChanged {}
        let snapshots = await service.snapshots()
        XCTAssertTrue(snapshots.isEmpty)
    }

    func testSnapshotsSurviveRestartAndDoNotCollideOnSanitizedNames() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let service = CodexAccountSnapshotService(codexDirectory: dir)
        try await service.save(auth("a"), for: "a+b@example.invalid")
        try await service.save(auth("b"), for: "a_b@example.invalid")
        let restarted = CodexAccountSnapshotService(codexDirectory: dir)
        let snapshots = await restarted.snapshots()
        XCTAssertEqual(Set(snapshots.map(\.accountKey)), ["a+b@example.invalid", "a_b@example.invalid"])
        XCTAssertEqual(Set(snapshots.map(\.url)).count, 2)
    }

    func testRefreshUpdatesSnapshotButNotAnotherActiveAccount() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let service = CodexAccountSnapshotService(codexDirectory: dir)
        let other = try auth("b")
        try other.write(to: dir.appendingPathComponent("auth.json"))
        try await service.save(auth("a"), for: "a")
        let refreshed = CodexCLIQuotaFetcher.TokenRefresh(accessToken: "new-access", refreshToken: "new-refresh", idToken: nil, expiresIn: 3600)
        try await service.persistRefresh(refreshed, originalRefreshToken: "fake-refresh-a")
        let saved = await service.snapshotAuthData(for: "a")
        let decoded = try JSONDecoder().decode(CodexCLIAuthFile.self, from: XCTUnwrap(saved))
        XCTAssertEqual(decoded.tokens?.accessToken, "new-access")
        XCTAssertEqual(decoded.tokens?.refreshToken, "new-refresh")
        XCTAssertEqual(try Data(contentsOf: dir.appendingPathComponent("auth.json")), other)
        // A late response for an already rotated token must not replace the newer credential.
        try await service.persistRefresh(.init(accessToken: "stale", refreshToken: nil, idToken: nil, expiresIn: nil), originalRefreshToken: "fake-refresh-a")
        let after = await service.snapshotAuthData(for: "a")
        XCTAssertEqual(after, saved)
    }

    func testRefreshUpdatesActiveAndSavedCopyTogether() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let service = CodexAccountSnapshotService(codexDirectory: dir)
        try await service.activate(auth("a"), accountKey: "a")
        try await service.persistRefresh(.init(accessToken: "new", refreshToken: "rotated", idToken: nil, expiresIn: nil), originalRefreshToken: "fake-refresh-a")
        let current = await service.currentAuthData()
        let saved = await service.snapshotAuthData(for: "a")
        XCTAssertEqual(current, saved)
        let json = try JSONSerialization.jsonObject(with: XCTUnwrap(current)) as? [String: Any]
        XCTAssertEqual(json?["custom_field"] as? String, "preserved")
    }

    func testChoosesRefreshedSnapshotOverStaleCredentialSource() throws {
        let old = try auth("a")
        var json = try XCTUnwrap(JSONSerialization.jsonObject(with: old) as? [String: Any])
        json["last_refresh"] = "2026-10-12T00:00:00Z"
        var tokens = try XCTUnwrap(json["tokens"] as? [String: Any])
        tokens["refresh_token"] = "rotated"
        json["tokens"] = tokens
        let fresh = try JSONSerialization.data(withJSONObject: json)
        XCTAssertEqual(CodexAccountSnapshotService.mostRecentAuth(in: [fresh, old]), fresh)
        XCTAssertEqual(CodexAccountSnapshotService.mostRecentAuth(in: [old, fresh]), fresh)
    }

    func testDiscoversOldSnapshotsWithoutMetadataAndIgnoresSavedConfig() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let savedDirectory = dir.appendingPathComponent("quotio-accounts")
        try FileManager.default.createDirectory(at: savedDirectory, withIntermediateDirectories: true)
        let target = try auth("b", email: "b@example.invalid")
        try target.write(to: savedDirectory.appendingPathComponent("b_example.invalid.auth.json"))
        try Data("old config".utf8).write(to: savedDirectory.appendingPathComponent("b_example.invalid.config.toml"))
        let service = CodexAccountSnapshotService(codexDirectory: dir)
        let snapshots = await service.snapshots()
        XCTAssertEqual(snapshots.map(\.accountKey), ["b@example.invalid"])
        let saved = await service.snapshotAuthData(for: "b@example.invalid")
        try await service.activate(XCTUnwrap(saved), accountKey: "b@example.invalid")
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent("config.toml").path))
    }

    func testSymlinkDestinationDoesNotModifyReferencedFile() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let service = CodexAccountSnapshotService(codexDirectory: dir)
        let original = try auth("a")
        let referenced = dir.appendingPathComponent("external.json")
        try original.write(to: referenced)
        try FileManager.default.createSymbolicLink(at: dir.appendingPathComponent("auth.json"), withDestinationURL: referenced)
        do {
            try await service.activate(auth("b"), accountKey: "b")
            XCTFail("Symlink destination must be rejected")
        } catch {}
        XCTAssertEqual(try Data(contentsOf: referenced), original)
    }
}
