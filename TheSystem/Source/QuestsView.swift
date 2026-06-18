//
//  QuestsView.swift
//  The System
//
//  Daily quests. Clear them all or face the penalty zone.
//

import SwiftUI

struct QuestsView: View {
    @EnvironmentObject var store: SystemStore
    @State private var showingAdd = false

    private var cleared: Int { store.quests.filter { $0.isComplete }.count }

    var body: some View {
        ScrollView {
            VStack(spacing: 8) {

                SystemPanel(header: "DAILY QUEST") {
                    Text("WARNING: Clear all quests before the day ends or enter the Penalty Zone.")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(SystemTheme.danger)
                    HStack {
                        Text("PROGRESS")
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.7))
                        Spacer()
                        Text("\(cleared)/\(store.quests.count)")
                            .font(.system(.caption2, design: .monospaced).weight(.bold))
                            .foregroundStyle(.white)
                    }
                    SystemBar(value: cleared, max: store.quests.count)
                }

                ForEach(store.quests) { quest in
                    QuestRow(quest: quest)
                }

                Button {
                    showingAdd = true
                } label: {
                    Label("Add Quest", systemImage: "plus.circle.fill")
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .tint(SystemTheme.accent)
            }
            .padding(.horizontal, 4)
            .padding(.bottom, 8)
        }
        .background(SystemBackground())
        .sheet(isPresented: $showingAdd) {
            AddQuestView()
        }
    }
}

struct QuestRow: View {
    @EnvironmentObject var store: SystemStore
    let quest: Quest

    var body: some View {
        Button {
            store.completeQuest(quest)
        } label: {
            HStack(spacing: 8) {
                Image(systemName: quest.isComplete ? "checkmark.seal.fill" : "circle")
                    .font(.system(size: 16))
                    .foregroundStyle(quest.isComplete ? SystemTheme.accentBright : .white.opacity(0.5))

                VStack(alignment: .leading, spacing: 2) {
                    Text(quest.title)
                        .font(.system(.caption, design: .monospaced).weight(.medium))
                        .foregroundStyle(.white)
                        .strikethrough(quest.isComplete)
                    Text("+\(quest.xpReward) XP · +\(quest.statRewardAmount) \(quest.statReward.rawValue)")
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(SystemTheme.accentBright.opacity(0.9))
                }
                Spacer()
                if quest.isBoss {
                    Image(systemName: "crown.fill")
                        .font(.system(size: 12))
                        .foregroundStyle(SystemTheme.gold)
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(SystemTheme.panelFill)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke((quest.isBoss ? SystemTheme.gold : SystemTheme.accent).opacity(quest.isComplete ? 0.35 : 0.85),
                            lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
        .disabled(quest.isComplete)
        .swipeActions {
            Button(role: .destructive) {
                store.removeQuest(quest)
            } label: {
                Image(systemName: "trash")
            }
        }
    }
}

// MARK: - Add quest

struct AddQuestView: View {
    @EnvironmentObject var store: SystemStore
    @Environment(\.dismiss) private var dismiss

    @State private var title = ""
    @State private var xp = 30
    @State private var stat: Stat = .strength
    @State private var isBoss = false

    var body: some View {
        ScrollView {
            VStack(spacing: 10) {
                TextField("Quest name", text: $title)
                    .font(.system(.caption, design: .monospaced))

                Stepper("XP: \(xp)", value: $xp, in: 10...300, step: 10)
                    .font(.system(.caption, design: .monospaced))

                Picker("Stat", selection: $stat) {
                    ForEach(Stat.allCases) { s in
                        Text(s.rawValue).tag(s)
                    }
                }
                .font(.system(.caption, design: .monospaced))

                Toggle("Boss Quest (grants a Shadow)", isOn: $isBoss)
                    .font(.system(.caption2, design: .monospaced))
                    .tint(SystemTheme.gold)

                Button {
                    let name = title.trimmingCharacters(in: .whitespaces)
                    guard !name.isEmpty else { return }
                    store.addQuest(title: name, xp: xp, stat: stat, isBoss: isBoss)
                    dismiss()
                } label: {
                    Text("ACCEPT")
                        .font(.system(.caption, design: .monospaced).weight(.bold))
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(SystemTheme.accent)
                .disabled(title.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding(.horizontal, 4)
        }
        .background(SystemBackground())
    }
}
