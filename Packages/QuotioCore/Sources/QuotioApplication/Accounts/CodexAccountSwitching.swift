import Foundation

public struct CodexAccountSwitchStatus: Codable, Equatable, Sendable {
    public var currentAccountIds: [String]
    public var availableAccountIds: [String]

    public init(currentAccountIds: [String] = [], availableAccountIds: [String] = []) {
        self.currentAccountIds = currentAccountIds
        self.availableAccountIds = availableAccountIds
    }
}

public enum CodexAccountSwitchFailure: Error, Sendable {
    case unavailable
    case failed
}
