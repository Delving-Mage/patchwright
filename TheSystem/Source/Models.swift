//
//  Models.swift
//  The System
//
//  Core data models for the Solo Leveling–style life RPG.
//

import Foundation
import SwiftUI

// MARK: - Stat

/// The five hunter attributes, mirroring the System's status window.
enum Stat: String, Codable, CaseIterable, Identifiable {
    case strength     = "STR"
    case agility      = "AGI"
    case vitality     = "VIT"
    case intelligence = "INT"
    case perception   = "PER"

    var id: String { rawValue }

    var fullName: String {
        switch self {
        case .strength:     return "Strength"
        case .agility:      return "Agility"
        case .vitality:     return "Vitality"
        case .intelligence: return "Intelligence"
        case .perception:   return "Perception"
        }
    }

    var icon: String {
        switch self {
        case .strength:     return "figure.strengthtraining.traditional"
        case .agility:      return "figure.run"
        case .vitality:     return "heart.fill"
        case .intelligence: return "brain.head.profile"
        case .perception:   return "eye.fill"
        }
    }
}

// MARK: - StatBlock

/// A concrete set of attribute values. Stored explicitly (rather than a
/// dictionary) so it round-trips cleanly through Codable / JSON.
struct StatBlock: Codable, Hashable {
    var strength: Int     = 10
    var agility: Int      = 10
    var vitality: Int     = 10
    var intelligence: Int = 10
    var perception: Int   = 10

    subscript(_ stat: Stat) -> Int {
        get {
            switch stat {
            case .strength:     return strength
            case .agility:      return agility
            case .vitality:     return vitality
            case .intelligence: return intelligence
            case .perception:   return perception
            }
        }
        set {
            switch stat {
            case .strength:     strength = newValue
            case .agility:      agility = newValue
            case .vitality:     vitality = newValue
            case .intelligence: intelligence = newValue
            case .perception:   perception = newValue
            }
        }
    }

    var total: Int { strength + agility + vitality + intelligence + perception }
}

// MARK: - Rank

/// Hunter rank, derived from level just like the Association grades it.
enum Rank: String, Codable, CaseIterable {
    case e = "E", d = "D", c = "C", b = "B", a = "A", s = "S", monarch = "MONARCH"

    static func forLevel(_ level: Int) -> Rank {
        switch level {
        case ..<10:  return .e
        case ..<20:  return .d
        case ..<30:  return .c
        case ..<40:  return .b
        case ..<50:  return .a
        case ..<70:  return .s
        default:     return .monarch
        }
    }

    var color: Color {
        switch self {
        case .e: return Color(red: 0.55, green: 0.60, blue: 0.65)
        case .d: return Color(red: 0.45, green: 0.85, blue: 0.55)
        case .c: return Color(red: 0.40, green: 0.70, blue: 1.00)
        case .b: return Color(red: 0.65, green: 0.45, blue: 1.00)
        case .a: return Color(red: 1.00, green: 0.55, blue: 0.30)
        case .s: return Color(red: 1.00, green: 0.30, blue: 0.40)
        case .monarch: return Color(red: 0.65, green: 0.20, blue: 1.00)
        }
    }
}

// MARK: - Quest

/// A real-activity metric a quest can be auto-cleared from, via HealthKit.
enum HealthMetric: String, Codable, CaseIterable, Identifiable {
    case steps
    case distanceKm
    case activeEnergy

    var id: String { rawValue }

    var label: String {
        switch self {
        case .steps:        return "Steps"
        case .distanceKm:   return "Distance (km)"
        case .activeEnergy: return "Active Energy (kcal)"
        }
    }

    var unitSuffix: String {
        switch self {
        case .steps:        return "steps"
        case .distanceKm:   return "km"
        case .activeEnergy: return "kcal"
        }
    }
}

/// A task the hunter must clear. Boss quests grant a shadow on completion.
/// A quest may also be linked to a `HealthMetric` so the System auto-clears
/// it once your real activity reaches `healthTarget`.
struct Quest: Identifiable, Codable, Hashable {
    var id: UUID = UUID()
    var title: String
    var detail: String = ""
    var xpReward: Int
    var statReward: Stat
    var statRewardAmount: Int = 1
    var isComplete: Bool = false
    var isBoss: Bool = false
    var healthMetric: HealthMetric? = nil   // optional → backward-compatible saves
    var healthTarget: Double? = nil

    /// The mandatory daily quest set Jinwoo receives from the System.
    static var defaultDailies: [Quest] {
        [
            Quest(title: "100 Push-ups",  detail: "Daily training", xpReward: 30, statReward: .strength),
            Quest(title: "100 Sit-ups",   detail: "Daily training", xpReward: 30, statReward: .vitality),
            Quest(title: "100 Squats",    detail: "Daily training", xpReward: 30, statReward: .strength),
            Quest(title: "10 km Run",     detail: "Daily training", xpReward: 50, statReward: .agility,
                  healthMetric: .distanceKm, healthTarget: 10),
            Quest(title: "10,000 Steps",  detail: "Stay on the move", xpReward: 40, statReward: .agility,
                  healthMetric: .steps, healthTarget: 10_000),
            Quest(title: "Read / Study 30 min", detail: "Sharpen the mind", xpReward: 40, statReward: .intelligence)
        ]
    }
}

// MARK: - Shadow

/// A reward extracted ("Arise") from clearing a boss quest. Your shadow army.
struct Shadow: Identifiable, Codable, Hashable {
    var id: UUID = UUID()
    var name: String
    var power: Int
    var dateExtracted: Date = Date()
    var icon: String = "figure.stand"
}

// MARK: - Job

struct JobOption: Identifiable, Hashable {
    let id = UUID()
    let title: String
    let requiredLevel: Int
    let blurb: String
    let icon: String
}

enum JobCatalog {
    static let all: [JobOption] = [
        JobOption(title: "Fighter",      requiredLevel: 5,  blurb: "Front-line striker.",          icon: "figure.martial.arts"),
        JobOption(title: "Mage",         requiredLevel: 5,  blurb: "Master of mana.",              icon: "sparkles"),
        JobOption(title: "Assassin",     requiredLevel: 5,  blurb: "Strike from the dark.",        icon: "eye.slash"),
        JobOption(title: "Tank",         requiredLevel: 5,  blurb: "Immovable wall.",              icon: "shield.fill"),
        JobOption(title: "Necromancer",  requiredLevel: 20, blurb: "Command the fallen.",          icon: "wand.and.stars"),
        JobOption(title: "Shadow Monarch", requiredLevel: 50, blurb: "Sovereign of the dead.",     icon: "crown.fill")
    ]

    static func unlocked(for level: Int) -> [JobOption] {
        all.filter { $0.requiredLevel <= level }
    }
}

// MARK: - Player

struct Player: Codable {
    var name: String = "HUNTER"
    var level: Int = 1
    var xp: Int = 0
    var statPoints: Int = 0
    var stats: StatBlock = StatBlock()
    var job: String = "None"
    var titles: [String] = []
    var shadows: [Shadow] = []
    var streak: Int = 0
    var fatigue: Int = 0
    var lastReset: Date = .distantPast

    var rank: Rank { Rank.forLevel(level) }

    /// Total combat power — a quick "how strong am I" number.
    var power: Int {
        stats.total * 3 + level * 10 + shadows.reduce(0) { $0 + $1.power }
    }
}
