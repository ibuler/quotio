import QuotioApplication
import SwiftUI

struct CodexAccountSwitchButton: View {
    @Environment(AccountsScreenModel.self) private var accounts
    let accountID: String

    var body: some View {
        if accounts.canSwitchCodexAccount(id: accountID) {
            Button {
                Task { await accounts.switchCodexAccount(id: accountID) }
            } label: {
                Label("codex.account.switchAction".localized(), systemImage: "arrow.left.arrow.right")
            }
            .buttonStyle(.borderless)
            .disabled(accounts.switchingCodexAccountID != nil)
            .help("codex.account.loadHelp".localized())
        } else if accounts.codexSwitchStatus.currentAccountIds.contains(accountID) {
            Text("codex.account.current".localized())
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

struct CodexSwitchResultModifier: ViewModifier {
    @Environment(AccountsScreenModel.self) private var accounts

    func body(content: Content) -> some View {
        content.alert("codex.account.switchTitle".localized(), isPresented: Binding(
            get: { accounts.codexSwitchMessage != nil },
            set: { if !$0 { accounts.codexSwitchMessage = nil } }
        )) {
            Button("action.ok".localized(), role: .cancel) { accounts.codexSwitchMessage = nil }
        } message: {
            Text(accounts.codexSwitchMessage ?? "")
        }
    }
}
