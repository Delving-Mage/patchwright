//
//  Notifications.swift
//  The System
//
//  The dramatic System pop-ups: Level Up and the Penalty Zone.
//

import SwiftUI

// MARK: - Level Up

struct LevelUpView: View {
    @EnvironmentObject var store: SystemStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ZStack {
            SystemBackground()
            VStack(spacing: 10) {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.system(size: 40))
                    .foregroundStyle(SystemTheme.accentBright)
                    .shadow(color: SystemTheme.accent, radius: 12)

                Text("LEVEL UP")
                    .font(.system(.title3, design: .monospaced).weight(.black))
                    .tracking(3)
                    .foregroundStyle(.white)

                Text("You have reached Level \(store.lastLevelGained).")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(SystemTheme.accentBright)
                    .multilineTextAlignment(.center)

                Text("+3 assignable points")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.7))

                Button("CONTINUE") { dismiss() }
                    .font(.system(.caption, design: .monospaced).weight(.bold))
                    .buttonStyle(.borderedProminent)
                    .tint(SystemTheme.accent)
            }
            .padding()
        }
    }
}

// MARK: - Penalty Zone

struct PenaltyView: View {
    @EnvironmentObject var store: SystemStore

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            RadialGradient(colors: [SystemTheme.danger.opacity(0.35), .clear],
                           center: .center, startRadius: 0, endRadius: 200)
                .ignoresSafeArea()

            ScrollView {
                VStack(spacing: 10) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 38))
                        .foregroundStyle(SystemTheme.danger)
                        .shadow(color: SystemTheme.danger, radius: 12)

                    Text("PENALTY ZONE")
                        .font(.system(.title3, design: .monospaced).weight(.black))
                        .tracking(2)
                        .foregroundStyle(SystemTheme.danger)

                    Text("You failed to complete the Daily Quest. The penalty has been applied.")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.white.opacity(0.85))
                        .multilineTextAlignment(.center)

                    VStack(alignment: .leading, spacing: 3) {
                        Text("· Streak reset to 0")
                        Text("· Fatigue +30")
                        Text("· EXP lost")
                    }
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(SystemTheme.danger.opacity(0.9))
                    .frame(maxWidth: .infinity, alignment: .leading)

                    Button {
                        store.endurePenalty()
                    } label: {
                        Text("ENDURE")
                            .font(.system(.caption, design: .monospaced).weight(.bold))
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(SystemTheme.danger)
                }
                .padding()
            }
        }
    }
}
