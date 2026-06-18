//
//  SettingsView.swift
//  The System
//
//  Control the daily reminder notification and connect HealthKit.
//

import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var store: SystemStore
    @EnvironmentObject var health: HealthManager

    // Persisted independently of the save file, so it's backward compatible.
    @AppStorage("remindersEnabled") private var remindersEnabled = false
    @AppStorage("reminderHour")     private var reminderHour = 20

    var body: some View {
        ScrollView {
            VStack(spacing: 8) {

                SystemPanel(header: "DAILY REMINDER") {
                    Toggle(isOn: $remindersEnabled) {
                        Text("System Alert")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.white)
                    }
                    .tint(SystemTheme.accent)
                    .onChange(of: remindersEnabled) { _, on in
                        if on {
                            NotificationManager.requestAuthorization()
                            NotificationManager.scheduleDailyReminder(hour: reminderHour)
                        } else {
                            NotificationManager.cancelDailyReminder()
                        }
                    }

                    if remindersEnabled {
                        Picker("Time", selection: $reminderHour) {
                            ForEach(0..<24, id: \.self) { h in
                                Text(String(format: "%02d:00", h)).tag(h)
                            }
                        }
                        .font(.system(.caption, design: .monospaced))
                        .onChange(of: reminderHour) { _, h in
                            NotificationManager.scheduleDailyReminder(hour: h)
                        }

                        Text("A warning will ping daily at \(String(format: "%02d:00", reminderHour)) if your quest is unfinished.")
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.55))
                    }
                }

                SystemPanel(header: "HEALTH SYNC", tint: SystemTheme.gold) {
                    if HealthManager.isAvailable {
                        HStack {
                            Image(systemName: health.authorized ? "heart.fill" : "heart")
                                .foregroundStyle(SystemTheme.danger)
                            Text(health.authorized ? "Connected" : "Not connected")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.white)
                        }
                        Button {
                            Task { await health.requestAuthorization() }
                        } label: {
                            Text(health.authorized ? "Re-check Access" : "Connect Health")
                                .font(.system(.caption2, design: .monospaced).weight(.bold))
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .tint(SystemTheme.accent)

                        Text("Links the Run / Steps quests to your real activity. Use \"Sync Health\" on the Quests screen.")
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.55))
                    } else {
                        Text("HealthKit is not available on this device.")
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.6))
                    }
                }

                SystemPanel(header: "SYSTEM") {
                    Button(role: .destructive) {
                        store.resetAll()
                    } label: {
                        Label("Reset Progress", systemImage: "arrow.counterclockwise")
                            .font(.system(.caption2, design: .monospaced))
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .tint(SystemTheme.danger)
                }
            }
            .padding(.horizontal, 4)
            .padding(.bottom, 8)
        }
        .background(SystemBackground())
    }
}
