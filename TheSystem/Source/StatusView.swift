//
//  StatusView.swift
//  The System
//
//  The character sheet — your status window.
//

import SwiftUI

struct StatusView: View {
    @EnvironmentObject var store: SystemStore

    var body: some View {
        ScrollView {
            VStack(spacing: 8) {

                SystemPanel(header: "STATUS") {
                    HStack(spacing: 10) {
                        RankBadge(rank: store.player.rank)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(store.player.name)
                                .font(.system(.headline, design: .monospaced).weight(.bold))
                                .foregroundStyle(.white)
                            Text("LV \(store.player.level)  ·  \(store.player.job)")
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(SystemTheme.accentBright)
                        }
                        Spacer()
                    }

                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text("EXP")
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.white.opacity(0.7))
                            Spacer()
                            Text("\(store.player.xp) / \(store.xpToNext)")
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.white.opacity(0.7))
                        }
                        SystemBar(value: store.player.xp, max: store.xpToNext)
                    }
                    .padding(.top, 2)
                }

                SystemPanel(header: "CONDITION") {
                    StatRow(label: "POWER", value: "\(store.player.power)", icon: "bolt.fill", tint: SystemTheme.gold)
                    StatRow(label: "STREAK", value: "\(store.player.streak) days", icon: "flame.fill", tint: SystemTheme.gold)
                    VStack(alignment: .leading, spacing: 3) {
                        StatRow(label: "FATIGUE", value: "\(store.player.fatigue)/100", icon: "moon.zzz.fill",
                                tint: SystemTheme.danger)
                        SystemBar(value: store.player.fatigue, max: 100, tint: SystemTheme.danger)
                    }
                }

                SystemPanel(header: "ATTRIBUTES") {
                    ForEach(Stat.allCases) { stat in
                        StatRow(label: stat.rawValue,
                                value: "\(store.player.stats[stat])",
                                icon: stat.icon)
                    }
                    if store.player.statPoints > 0 {
                        Divider().background(SystemTheme.accent.opacity(0.4))
                        Text("\(store.player.statPoints) points to assign →")
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(SystemTheme.accentBright)
                    }
                }

                if !store.player.titles.isEmpty {
                    SystemPanel(header: "TITLES", tint: SystemTheme.gold) {
                        ForEach(store.player.titles, id: \.self) { t in
                            StatRow(label: t, value: "★", icon: "rosette", tint: SystemTheme.gold)
                        }
                    }
                }
            }
            .padding(.horizontal, 4)
            .padding(.bottom, 8)
        }
        .background(SystemBackground())
    }
}
