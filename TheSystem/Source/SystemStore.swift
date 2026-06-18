//
//  SystemStore.swift
//  The System
//
//  The "System" itself: holds state, runs the leveling/penalty rules,
//  and persists everything to UserDefaults.
//

import Foundation
import SwiftUI

@MainActor
final class SystemStore: ObservableObject {

    @Published var player: Player
    @Published var quests: [Quest]

    // Transient UI signals
    @Published var showLevelUp = false
    @Published var lastLevelGained = 0
    @Published var penaltyActive = false
    @Published var ariseBanner: Shadow? = nil

    private let saveKey = "the_system_save_v1"

    // Pool of names for extracted shadows.
    private let shadowNames = ["Igris", "Tank", "Iron", "Tusk", "Beru",
                               "Kaisel", "Greed", "Fang", "Jima", "Kargalgan"]

    // MARK: - Init / Persistence

    init() {
        if let data = UserDefaults.standard.data(forKey: saveKey),
           let saved = try? JSONDecoder().decode(SaveState.self, from: data) {
            player = saved.player
            quests = saved.quests
        } else {
            player = Player()
            quests = Quest.defaultDailies
        }
        checkDailyReset()
    }

    private struct SaveState: Codable {
        var player: Player
        var quests: [Quest]
    }

    func save() {
        let state = SaveState(player: player, quests: quests)
        if let data = try? JSONEncoder().encode(state) {
            UserDefaults.standard.set(data, forKey: saveKey)
        }
    }

    // MARK: - Leveling

    /// EXP required to advance from the current level to the next.
    var xpToNext: Int {
        max(50, Int(100.0 * pow(Double(player.level), 1.4)))
    }

    func addXP(_ amount: Int) {
        guard amount > 0 else { return }
        player.xp += amount
        while player.xp >= xpToNext {
            player.xp -= xpToNext
            player.level += 1
            player.statPoints += 3
            lastLevelGained = player.level
            showLevelUp = true
            awardRankTitleIfNeeded()
        }
    }

    private func awardRankTitleIfNeeded() {
        let title: String
        switch player.rank {
        case .s:       title = "S-Rank Hunter"
        case .monarch: title = "Shadow Monarch"
        default:       return
        }
        if !player.titles.contains(title) {
            player.titles.append(title)
        }
    }

    // MARK: - Quests

    func completeQuest(_ quest: Quest) {
        guard let idx = quests.firstIndex(where: { $0.id == quest.id }),
              !quests[idx].isComplete else { return }

        quests[idx].isComplete = true
        let q = quests[idx]
        player.stats[q.statReward] += q.statRewardAmount
        addXP(q.xpReward)

        if q.isBoss { arise(level: player.level) }

        // Clearing every quest in a day eases fatigue.
        if quests.allSatisfy({ $0.isComplete }) {
            player.fatigue = max(0, player.fatigue - 20)
        }
        save()
    }

    func addQuest(title: String, xp: Int, stat: Stat, isBoss: Bool) {
        let q = Quest(title: title, xpReward: xp, statReward: stat,
                      statRewardAmount: isBoss ? 3 : 1, isBoss: isBoss)
        quests.append(q)
        save()
    }

    func removeQuest(_ quest: Quest) {
        quests.removeAll { $0.id == quest.id }
        save()
    }

    // MARK: - Stats & Jobs

    func allocate(_ stat: Stat, amount: Int = 1) {
        guard player.statPoints >= amount else { return }
        player.stats[stat] += amount
        player.statPoints -= amount
        save()
    }

    func setJob(_ job: JobOption) {
        guard player.level >= job.requiredLevel else { return }
        player.job = job.title
        if !player.titles.contains(job.title) {
            player.titles.append(job.title)
        }
        save()
    }

    // MARK: - Shadow army

    func arise(level: Int) {
        let shadow = Shadow(
            name: shadowNames.randomElement() ?? "Shadow",
            power: level * 10 + Int.random(in: 5...25)
        )
        player.shadows.append(shadow)
        ariseBanner = shadow
        save()
    }

    // MARK: - Daily reset & penalty

    /// Called on launch / appear. If a new day has started, grades the
    /// previous day: all quests cleared -> streak up, otherwise penalty.
    func checkDailyReset() {
        let cal = Calendar.current
        guard !cal.isDateInToday(player.lastReset) else { return }

        let hadQuests = !quests.isEmpty
        let allCleared = quests.allSatisfy { $0.isComplete }

        // Don't punish a brand-new save with no history.
        if player.lastReset != .distantPast && hadQuests {
            if allCleared {
                player.streak += 1
            } else {
                player.streak = 0
                triggerPenalty()
            }
        }

        for i in quests.indices { quests[i].isComplete = false }
        player.lastReset = Date()
        save()
    }

    func triggerPenalty() {
        penaltyActive = true
        player.fatigue = min(100, player.fatigue + 30)
        player.xp = max(0, player.xp - xpToNext / 4)
    }

    func endurePenalty() {
        penaltyActive = false
        player.fatigue = max(0, player.fatigue - 10)
        save()
    }

    // MARK: - Debug / reset

    func resetAll() {
        player = Player()
        quests = Quest.defaultDailies
        player.lastReset = Date()
        save()
    }
}
