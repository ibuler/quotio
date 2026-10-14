import Foundation
import QuotioApplication
import QuotioDomain

struct StatusBarMenuAccountSnapshot: Equatable, Sendable {
    let id: QuotaAccountID
    let email: String
    let quota: ProviderQuota
    let subscription: QuotaSubscriptionInfo?
    let isRefreshing: Bool
    let isRefreshBlocked: Bool
    var canSwitchCodex: Bool = false
}

struct StatusBarMenuProviderSnapshot: Equatable, Sendable {
    let displayName: String
    let provider: QuotaProvider
    let accounts: [StatusBarMenuAccountSnapshot]
    let isRefreshing: Bool
    let supportsScopedRefresh: Bool
}

struct StatusBarMenuDisplaySettings: Equatable, Sendable {
    let quotaDisplayMode: QuotaDisplayMode
    let quotaDisplayStyle: QuotaDisplayStyle
    let hideSensitiveInfo: Bool
    let modelAggregationMode: ModelAggregationMode


}

public struct StatusBarMenuSnapshot: Equatable, Sendable {
    let providers: [StatusBarMenuProviderSnapshot]
    let selectedProvider: QuotaProvider?
    let isLoadingQuotas: Bool
    let canRefresh: Bool
    let displaySettings: StatusBarMenuDisplaySettings
    let language: AppLanguage
}

public enum StatusBarMenuSnapshotMapper {
    nonisolated public static func makeSnapshot(
        monitorAccounts: [Account],
        quota: QuotaSnapshot,
        menuBarPreferences: MenuBarPreferences,
        language: AppLanguage,
        trackingPreferences: ProviderTrackingPreferences = ProviderTrackingPreferences(),
        codexSwitchStatus: CodexAccountSwitchStatus = .init(),
        isSwitchingCodex: Bool = false
    ) -> StatusBarMenuSnapshot {
        let disabledAccounts = Set(monitorAccounts.lazy.filter(\.isDisabled).map {
            "\($0.providerID.rawValue):\($0.accountKey)"
        })
        let availableProviders = Set(quota.quotas.compactMap { provider, accounts in
            trackingPreferences.isEnabled(provider) && accounts.contains { accountKey, _ in
                !disabledAccounts.contains("\(provider.rawValue):\(accountKey)")
            } ? provider : nil
        })

        func displayName(_ provider: QuotaProvider) -> String { quota.providerNames[provider] ?? provider.displayName }
        let providers = availableProviders.sorted { displayName($0) < displayName($1) }.map { provider in
            let accounts = orderedAccounts(
                (quota.quotas[provider] ?? [:]).filter { accountKey, _ in
                    !disabledAccounts.contains("\(provider.rawValue):\(accountKey)")
                }
            ).map { account in
                let accountID = QuotaAccountID(provider: provider, accountKey: account.accountKey)
                return StatusBarMenuAccountSnapshot(
                    id: accountID,
                    email: account.email,
                    quota: account.data,
                    subscription: quota.subscriptions[provider]?[account.accountKey],
                    isRefreshing: quota.refreshingProviders.contains(provider),
                    isRefreshBlocked: !quota.canRefresh || quota.refreshingProviders.contains(provider),
                    canSwitchCodex: provider == .codex && !isSwitchingCodex
                        && codexSwitchStatus.availableAccountIds.contains(account.accountKey)
                        && !codexSwitchStatus.currentAccountIds.contains(account.accountKey)
                )
            }
            return StatusBarMenuProviderSnapshot(
                displayName: displayName(provider),
                provider: provider,
                accounts: accounts,
                isRefreshing: quota.refreshingProviders.contains(provider),
                supportsScopedRefresh: quota.canRefresh
            )
        }

        return StatusBarMenuSnapshot(
            providers: providers,
            selectedProvider: menuBarPreferences.selectedProvider.flatMap { selected in
                providers.contains(where: { $0.provider == selected }) ? selected : nil
            },
            isLoadingQuotas: !quota.refreshingProviders.isEmpty,
            canRefresh: quota.canRefresh,
            displaySettings: StatusBarMenuDisplaySettings(
                quotaDisplayMode: menuBarPreferences.quotaDisplayMode,
                quotaDisplayStyle: menuBarPreferences.quotaDisplayStyle,
                hideSensitiveInfo: menuBarPreferences.hideSensitiveInfo,
                modelAggregationMode: menuBarPreferences.modelAggregationMode
            ),
            language: language
        )
    }

    nonisolated static func orderedAccounts(
        _ quotas: [String: ProviderQuota]
    ) -> [(accountKey: String, email: String, data: ProviderQuota)] {
        quotas.map { (accountKey: $0.key, email: $0.value.accountDisplayName ?? $0.key, data: $0.value) }
            .sorted {
                if $0.email == $1.email { return $0.accountKey < $1.accountKey }
                return $0.email.localizedStandardCompare($1.email) == .orderedAscending
            }
    }
}
