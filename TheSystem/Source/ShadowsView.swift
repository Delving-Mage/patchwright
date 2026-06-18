//
//  ShadowsView.swift
//  The System
//
//  Your shadow army — rewards extracted from boss quests.
//

import SwiftUI

struct ShadowsView: View {
    @EnvironmentObject var store: SystemStore

    private var armyPower: Int {
        store.player.shadows.reduce(0) { $0 + $1.power }
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 8) {

                SystemPanel(header: "SHADOW ARMY", tint: SystemTheme.gold) {
                    HStack {
                        Image(systemName: "person.3.fill")
                            .foregroundStyle(SystemTheme.accentBright)
                        Text("\(store.player.shadows.count) soldiers")
                            .font(.system(.caption, design: .monospaced).weight(.bold))
                            .foregroundStyle(.white)
                        Spacer()
                        Text("PWR \(armyPower)")
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(SystemTheme.gold)
                    }
                }

                if store.player.shadows.isEmpty {
                    SystemPanel {
                        VStack(spacing: 6) {
                            Image(systemName: "moon.stars.fill")
                                .font(.system(size: 22))
                                .foregroundStyle(SystemTheme.accent.opacity(0.7))
                            Text("No shadows yet.")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.white.opacity(0.8))
                            Text("Clear a Boss Quest to \"Arise\" your first soldier.")
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.white.opacity(0.55))
                                .multilineTextAlignment(.center)
                        }
                        .frame(maxWidth: .infinity)
                    }
                } else {
                    ForEach(store.player.shadows) { shadow in
                        HStack(spacing: 10) {
                            Image(systemName: shadow.icon)
                                .font(.system(size: 18))
                                .foregroundStyle(SystemTheme.accentBright)
                                .frame(width: 26)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(shadow.name)
                                    .font(.system(.caption, design: .monospaced).weight(.bold))
                                    .foregroundStyle(.white)
                                Text(shadow.dateExtracted, style: .date)
                                    .font(.system(size: 9, design: .monospaced))
                                    .foregroundStyle(.white.opacity(0.5))
                            }
                            Spacer()
                            Text("PWR \(shadow.power)")
                                .font(.system(.caption2, design: .monospaced).weight(.bold))
                                .foregroundStyle(SystemTheme.gold)
                        }
                        .padding(10)
                        .frame(maxWidth: .infinity)
                        .background(RoundedRectangle(cornerRadius: 8).fill(SystemTheme.panelFill))
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(SystemTheme.accent.opacity(0.6), lineWidth: 1))
                    }
                }
            }
            .padding(.horizontal, 4)
            .padding(.bottom, 8)
        }
        .background(SystemBackground())
    }
}
