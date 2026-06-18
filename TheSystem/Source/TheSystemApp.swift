//
//  TheSystemApp.swift
//  The System  ·  watchOS app
//
//  A Solo Leveling–style life RPG for Apple Watch.
//

import SwiftUI

@main
struct TheSystemApp: App {
    @StateObject private var store = SystemStore()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(store)
                .onChange(of: scenePhase) { _, phase in
                    if phase == .active { store.checkDailyReset() }
                }
        }
    }
}

struct RootView: View {
    @EnvironmentObject var store: SystemStore

    var body: some View {
        TabView {
            StatusView()
            QuestsView()
            StatsView()
            ShadowsView()
        }
        .tabViewStyle(.verticalPage)
        .background(SystemTheme.bg)
        .sheet(isPresented: $store.showLevelUp) {
            LevelUpView().environmentObject(store)
        }
        .sheet(isPresented: $store.penaltyActive) {
            PenaltyView()
                .environmentObject(store)
                .interactiveDismissDisabled()
        }
    }
}

#Preview {
    RootView().environmentObject(SystemStore())
}
