import Foundation
import QuotioApplication
import QuotioDomain
import UserNotifications

@MainActor
public final class UserNotificationCenterAdapter: NotificationDelivering {
    public typealias Localizer = @MainActor @Sendable (String) -> String

    private let center: UNUserNotificationCenter
    private let localize: Localizer
    private let now: @Sendable () -> Date

    public init(
        center: UNUserNotificationCenter = .current(),
        localize: @escaping Localizer,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.center = center
        self.localize = localize
        self.now = now
    }

    public func requestAuthorization() async -> NotificationAuthorizationStatus {
        await withCheckedContinuation { continuation in
            center.requestAuthorization(options: [.alert, .sound, .badge]) { @Sendable granted, _ in
                continuation.resume(returning: granted ? .authorized : .denied)
            }
        }
    }

    public func authorizationStatus() async -> NotificationAuthorizationStatus {
        let status = await withCheckedContinuation { continuation in
            center.getNotificationSettings { @Sendable settings in
                continuation.resume(returning: settings.authorizationStatus.rawValue)
            }
        }
        switch UNAuthorizationStatus(rawValue: status) {
        case .authorized:
            return .authorized
        case .denied, .provisional, .ephemeral:
            return .denied
        case .notDetermined:
            return .notDetermined
        case nil:
            return .denied
        @unknown default:
            return .denied
        }
    }

    public func deliver(_ notification: SemanticNotification) {
        let content = UNMutableNotificationContent()
        let identifier: String

        switch notification {
        case .quotaLow(let id, let provider, let account, let remainingPercent):
            identifier = "quota_\(id)"
            content.title = localize("notification.quotaLow.title")
            content.body = String(
                format: localize("notification.quotaLow.body"),
                provider,
                account,
                Int(remainingPercent)
            )
            content.categoryIdentifier = "quotaLow"
            content.sound = .default
        case .accountCooling(let provider, let account):
            identifier = "cooling_\(provider)_\(account)"
            content.title = localize("notification.cooling.title")
            content.body = String(format: localize("notification.cooling.body"), provider, account)
            content.categoryIdentifier = "accountCooling"
            content.sound = .default
        case .proxyCrashed(let exitCode):
            identifier = "proxy_crash_\(now().timeIntervalSince1970)"
            content.title = localize("notification.proxyCrash.title")
            content.body = String(format: localize("notification.proxyCrash.body"), exitCode)
            content.categoryIdentifier = "proxyCrashed"
            content.sound = .defaultCritical
        case .proxyStarted:
            identifier = "proxy_started"
            content.title = localize("notification.proxyStarted.title")
            content.body = localize("notification.proxyStarted.body")
            content.sound = .default
        case .proxyUpdateAvailable(let version):
            identifier = "upgrade_available_\(version)"
            content.title = localize("notification.upgradeAvailable.title")
            content.body = String(format: localize("notification.upgradeAvailable.body"), version)
            content.categoryIdentifier = "upgradeAvailable"
            content.sound = .default
        case .proxyUpdateSucceeded(let version):
            identifier = "upgrade_success_\(version)"
            content.title = localize("notification.upgrade.success.title")
            content.body = String(format: localize("notification.upgrade.success.body"), version)
            content.categoryIdentifier = "upgradeSuccess"
            content.sound = .default
        case .proxyUpdateFailed(let version, let failure):
            identifier = "upgrade_failed_\(version)"
            content.title = localize("notification.upgrade.failed.title")
            content.body = String(
                format: localize("notification.upgrade.failed.body"),
                version,
                proxyFailureNotificationReason(failure)
            )
            content.categoryIdentifier = "upgradeFailed"
            content.sound = .defaultCritical
        case .proxyRolledBack(let version):
            identifier = "rollback_\(version)"
            content.title = localize("notification.rollback.title")
            content.body = String(format: localize("notification.rollback.body"), version)
            content.categoryIdentifier = "rollback"
            content.sound = .default
        }

        center.add(UNNotificationRequest(identifier: identifier, content: content, trigger: nil))
    }

    public func removeAllPending() {
        center.removeAllPendingNotificationRequests()
    }

    public func removeAllDelivered() {
        center.removeAllDeliveredNotifications()
    }
}

func proxyFailureNotificationReason(_ failure: ProxyFailure) -> String {
    switch failure {
    case .binaryNotFound: "Binary not found"
    case .startupFailed: "Proxy startup failed"
    case .operationInProgress: "Another operation is in progress"
    case .network(let message),
         .downloadFailed(let message),
         .extractionFailed(let message),
         .installationFailed(let message),
         .dryRunFailed(let message),
         .rollbackFailed(let message): message
    case .noCompatibleBinary: "No compatible binary"
    case .checksumMissing: "No SHA256 checksum provided"
    case .checksumMismatch: "Checksum mismatch"
    case .compatibilityCheckFailed: "Compatibility check failed"
    case .noVersionAvailable: "No version available"
    case .versionAlreadyInstalled(let version): "Version \(version) is already installed"
    case .cannotDeleteCurrentVersion: "Cannot delete current version"
    case .cancelled: "Operation cancelled"
    }
}
