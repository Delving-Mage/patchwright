//
//  StatsView.swift
//  The System
//
//  Spend assignable points and change your job/class.
//

import SwiftUI

struct StatsView: View {
    @EnvironmentObject var store: SystemStore

    var body: some View {
        ScrollView {
            VStack(spacing: 8) {

                SystemPanel(header: "ASSIGNABLE POINTS") {
                    HStack {
                        Image(systemName: "plus.diamond.fill")
                            .foregroundStyle(SystemTheme.accentBright)
                        Text("\(store.player.statPoints) available")
                            .font(.system(.body, design: .monospaced).weight(.bold))
                            .foregroundStyle(.white)
                    }

                    ForEach(Stat.allCases) { stat in
                        HStack(spacing: 8) {
                            Image(systemName: stat.icon)
                                .font(.system(size: 12))
                                .foregroundStyle(SystemTheme.accentBright)
                                .frame(width: 18)
                            Text(stat.rawValue)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.white.opacity(0.85))
                            Spacer()
                            Text("\(store.player.stats[stat])")
                                .font(.system(.caption, design: .monospaced).weight(.bold))
                                .foregroundStyle(.white)
                                .frame(minWidth: 26)
                            Button {
                                store.allocate(stat)
                            } label: {
                                Image(systemName: "plus.circle.fill")
                                    .font(.system(size: 18))
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(store.player.statPoints > 0 ? SystemTheme.accent : .gray)
                            .disabled(store.player.statPoints <= 0)
                        }
                    }
                }

                SystemPanel(header: "JOB CHANGE", tint: SystemTheme.gold) {
                    Text("Current Class: \(store.player.job)")
                        .font(.system(.caption, design: .monospaced).weight(.bold))
                        .foregroundStyle(.white)

                    let unlocked = JobCatalog.unlocked(for: store.player.level)
                    if unlocked.isEmpty {
                        Text("Reach Lv 5 to unlock your first class.")
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.6))
                    } else {
                        ForEach(unlocked) { job in
                            Button {
                                store.setJob(job)
                            } label: {
                                HStack(spacing: 8) {
                                    Image(systemName: job.icon)
                                        .frame(width: 18)
                                    VStack(alignment: .leading, spacing: 1) {
                                        Text(job.title)
                                            .font(.system(.caption, design: .monospaced).weight(.bold))
                                        Text(job.blurb)
                                            .font(.system(size: 9, design: .monospaced))
                                            .foregroundStyle(.white.opacity(0.6))
                                    }
                                    Spacer()
                                    if store.player.job == job.title {
                                        Image(systemName: "checkmark")
                                            .foregroundStyle(SystemTheme.gold)
                                    }
                                }
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(.white)
                        }
                    }

                    // Locked classes (teaser)
                    ForEach(JobCatalog.all.filter { $0.requiredLevel > store.player.level }) { job in
                        HStack(spacing: 8) {
                            Image(systemName: "lock.fill").frame(width: 18)
                            Text("\(job.title) — Lv \(job.requiredLevel)")
                                .font(.system(.caption2, design: .monospaced))
                            Spacer()
                        }
                        .foregroundStyle(.white.opacity(0.4))
                    }
                }

                #if DEBUG
                Button("Reset System") { store.resetAll() }
                    .font(.system(.caption2, design: .monospaced))
                    .buttonStyle(.bordered)
                    .tint(SystemTheme.danger)
                #endif
            }
            .padding(.horizontal, 4)
            .padding(.bottom, 8)
        }
        .background(SystemBackground())
    }
}
