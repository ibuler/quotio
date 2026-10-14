import Foundation
import QuotioApplication
import QuotioDomain
import XCTest
@testable import QuotioPresentation

@MainActor
final class AccountScreenModelsTests: XCTestCase {
    func testCodexSwitchReloadsCurrentAccountAndIgnoresUnavailableTargets() async {
        let service = AccountScreenModelService(accounts: [], switchStatus: .init(currentAccountIds: ["old"], availableAccountIds: ["old", "new"]))
        let model = AccountsScreenModel(accountService: service)
        await model.reloadAccounts()
        XCTAssertFalse(model.canSwitchCodexAccount(id: "old"))
        XCTAssertTrue(model.canSwitchCodexAccount(id: "new"))
        await model.switchCodexAccount(id: "missing")
        var calls = await service.switchedIDs
        XCTAssertTrue(calls.isEmpty)
        await model.switchCodexAccount(id: "new")
        calls = await service.switchedIDs
        XCTAssertEqual(calls, ["new"])
        XCTAssertEqual(model.codexSwitchStatus.currentAccountIds, ["new"])
        XCTAssertTrue(model.canSwitchCodexAccount(id: "old"))
        XCTAssertNil(model.switchingCodexAccountID)
        XCTAssertEqual(model.codexSwitchMessage, "codex.account.loaded".localized())
    }

    func testCodexSwitchFailureKeepsCurrentAccountAndAllowsRetry() async {
        let service = AccountScreenModelService(accounts: [], switchStatus: .init(currentAccountIds: ["old"], availableAccountIds: ["old", "new"]), switchFails: true)
        let model = AccountsScreenModel(accountService: service)
        await model.reloadAccounts()
        await model.switchCodexAccount(id: "new")
        XCTAssertEqual(model.codexSwitchStatus.currentAccountIds, ["old"])
        XCTAssertEqual(model.codexSwitchMessage, "codex.account.switchFailed".localized())
        XCTAssertNil(model.switchingCodexAccountID)
        XCTAssertTrue(model.canSwitchCodexAccount(id: "new"))
    }

    func testAccountsModelDisplaysHostAccounts() async {
        let account = Account.make(
            providerID: AccountProviderID(rawValue: "codex"),
            accountKey: "person@example.com",
            source: .nativeCredential
        )
        let model = AccountsScreenModel(
            accountService: AccountScreenModelService(accounts: [account])
        )

        await model.reloadAccounts()

        XCTAssertEqual(model.accounts, [account])
        XCTAssertFalse(String(describing: model).contains("accessToken"))
    }

    func testAccountsModelConnectsNativeSourceOnlyAfterUserAction() async throws {
        let permission = NativeSourcePermission(
            provider: .factoryDroid,
            kind: "factory_native",
            location: "v2_keyring"
        )
        let service = AccountScreenModelService(accounts: [], permissions: [permission])
        let model = AccountsScreenModel(
            accountService: service
        )

        await model.registerDetectedNativeAccounts()
        XCTAssertEqual(model.nativeSourcePermissions, [permission])

        try await model.authorizeNativeSource(permission)
        XCTAssertTrue(model.nativeSourcePermissions.isEmpty)
        let authorized = await service.lastAuthorizedSource
        XCTAssertEqual(authorized, permission)
    }

    func testNativePermissionExplainsProviderSpecificKeychainReason() {
        XCTAssertEqual(
            NativeSourcePermission(
                provider: .antigravity,
                kind: "antigravity_native",
                location: "gemini_keychain"
            ).explanationLocalizationKey,
            "providers.nativePermission.antigravity"
        )
        XCTAssertEqual(
            NativeSourcePermission(
                provider: .factoryDroid,
                kind: "factory_native",
                location: "v2_login_keychain"
            ).explanationLocalizationKey,
            "providers.nativePermission.factory"
        )
    }

    func testAccountsModelReloadPreservesEmptyHostResult() async {
        let model = AccountsScreenModel(
            accountService: AccountScreenModelService(accounts: [])
        )

        await model.reloadAccounts()

        XCTAssertTrue(model.accounts.isEmpty)
    }

    func testAccountsModelForwardsHostIDsAndDisabledState() async throws {
        let owned = Account(
            identity: AccountIdentity(id: "vault-id", providerID: .init(rawValue: "codex"),
                accountKey: "same@example.com-pro"),
            displayName: "same@example.com", source: .quotioKeychain,
            credentialReference: "keychain", capabilities: [.disable, .delete], status: .disabled
        )
        let service = AccountScreenModelService(accounts: [owned])
        let model = AccountsScreenModel(accountService: service)

        await model.reloadAccounts()

        XCTAssertEqual(model.accounts.count, 1)
        let account = try XCTUnwrap(model.accounts.first)
        XCTAssertEqual(account.accountKey, owned.accountKey)
        XCTAssertEqual(account.id, owned.id)
        XCTAssertEqual(account.source, owned.source)
        XCTAssertEqual(account.credentialReference, owned.credentialReference)
        XCTAssertEqual(account.capabilities, owned.capabilities)
        XCTAssertTrue(account.isDisabled)
        await model.setDisabled(false, accountID: account.id)
        XCTAssertEqual(model.accounts.map(\.accountKey), [owned.accountKey])
        try await model.delete(accountID: account.id)
        let disabledID = await service.lastDisabledID
        let deletedID = await service.lastDeletedID
        XCTAssertEqual(disabledID, owned.id)
        XCTAssertEqual(deletedID, owned.id)
    }

    func testReloadDoesNotMergeDistinctHostAccounts() async {
        let provider = AccountProviderID(rawValue: "codex")
        let owned = Account.make(providerID: provider, accountKey: "same@example.com",
            source: .quotioKeychain, capabilities: [.disable, .delete])
        let legacy = Account.make(providerID: provider, accountKey: "same@example.com-pro",
            source: .legacyCLIProxy)
        let workspace = Account.make(providerID: provider, accountKey: "same@example.com-team",
            source: .legacyCLIProxy)
        let other = Account.make(providerID: .init(rawValue: "claude"),
            accountKey: "same@example.com-pro", source: .nativeCredential)
        let model = AccountsScreenModel(
            accountService: AccountScreenModelService(accounts: [legacy, owned, workspace, other]))

        await model.reloadAccounts()

        XCTAssertEqual(Set(model.accounts.map(\.id)), [owned.id, legacy.id, workspace.id, other.id])
        await model.reloadAccounts()
        XCTAssertEqual(Set(model.accounts.map(\.id)), [owned.id, legacy.id, workspace.id, other.id])
    }

    func testDownloadEligibilityRequiresAnAuthFileName() {
        let authFileAccount = AccountRowData(
            id: "auth-file",
            provider: .claude,
            displayName: "person@example.com",
            authFileName: "claude-person@example.com.json",
            source: .direct,
            status: nil,
            statusMessage: nil,
            isDisabled: false,
            canDelete: false
        )
        let customProviderAccount = AccountRowData(
            id: "custom-provider",
            provider: .glm,
            displayName: "GLM",
            source: .direct,
            status: "ready",
            statusMessage: nil,
            isDisabled: false,
            canDelete: true
        )

        XCTAssertTrue(authFileAccount.canDownloadAuthFile)
        XCTAssertFalse(customProviderAccount.canDownloadAuthFile)
    }

    func testOAuthModelPublishesSuccessAndRunsHandlerOnce() async {
        let providerID = AccountProviderID(rawValue: "claude")
        let controller = OAuthFlowController(authorizer: ImmediateOAuthAuthorizer())
        let model = OAuthScreenModel(controller: controller)
        var successCount = 0
        model.setSuccessHandler { successCount += 1 }

        await model.start(OAuthAuthorizationRequest(providerID: providerID))
        await waitUntil {
            if case .succeeded(let completedProvider, _) = model.state {
                return completedProvider == providerID
            }
            return false
        }

        XCTAssertEqual(successCount, 1)
        await model.shutdown()
        XCTAssertEqual(model.state, .idle)
    }

    private func waitUntil(
        timeout: Duration = .seconds(1),
        condition: @escaping @MainActor () -> Bool
    ) async {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        while clock.now < deadline {
            if condition() { return }
            await Task.yield()
        }
        XCTFail("Timed out waiting for condition")
    }
}

private actor AccountScreenModelService: AccountManaging {
    private let storedAccounts: [Account]
    private var permissions: [NativeSourcePermission]
    private(set) var lastDisabledID: String?
    private(set) var lastDeletedID: String?
    private(set) var lastAuthorizedSource: NativeSourcePermission?

    private var switchStatus: CodexAccountSwitchStatus
    private let switchFails: Bool
    private(set) var switchedIDs: [String] = []

    init(accounts: [Account], permissions: [NativeSourcePermission] = [], switchStatus: CodexAccountSwitchStatus = .init(), switchFails: Bool = false) {
        self.switchStatus = switchStatus
        self.switchFails = switchFails
        storedAccounts = accounts
        self.permissions = permissions
    }

    func codexSwitchStatus() -> CodexAccountSwitchStatus { switchStatus }
    func switchCodexAccount(id: String) throws {
        if switchFails { throw CodexAccountSwitchFailure.failed }
        switchedIDs.append(id)
        switchStatus.currentAccountIds = [id]
    }
    func registerDetectedNativeAccounts() {}
    func rescanNativeAccounts(for provider: QuotaProvider) {}
    func nativeDiscoverySnapshot() -> NativeDiscoverySnapshot { .init(permissions: permissions) }
    func authorizeNativeSource(_ source: NativeSourcePermission) {
        lastAuthorizedSource = source
        permissions.removeAll { $0 == source }
    }
    func accounts() -> [Account] { storedAccounts }
    func setDisabled(_ disabled: Bool, accountID: String) { lastDisabledID = accountID }
    func delete(accountID: String) { lastDeletedID = accountID }

    func renameResolvedAccount(id: String, userLabel: String?) async throws {}
    func setSourceEnabled(_ enabled: Bool, sourceID: String) async throws {}
    func unlinkSource(sourceID: String) async throws {}

    func saveAPIKey(
        providerID: AccountProviderID,
        label: String,
        apiKey: String,
        existingAccountID: String?,
        fields: [String: String] = [:]
    ) {}
}

private actor ImmediateOAuthAuthorizer: OAuthAuthorizing {
    func begin(
        request: OAuthAuthorizationRequest,
        attemptID: OAuthAttemptID,
        progress: @escaping @Sendable (OAuthPrompt) async -> Void
    ) -> OAuthAuthorizationOutcome {
        .completed(Account.make(
            providerID: request.providerID,
            accountKey: "person@example.com",
            source: .quotioKeychain,
            capabilities: [.disable, .delete]
        ))
    }

    func completeManualCode(
        _ code: String,
        providerID: AccountProviderID,
        attemptID: OAuthAttemptID
    ) -> Account {
        Account.make(
            providerID: providerID,
            accountKey: "person@example.com",
            source: .quotioKeychain
        )
    }

    func cancel(attemptID: OAuthAttemptID) {}
}
