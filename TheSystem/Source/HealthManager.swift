//
//  HealthManager.swift
//  The System
//
//  Reads today's real activity from HealthKit so the System can auto-clear
//  movement-based quests (run / steps / energy).
//
//  Requires (set up in Xcode):
//   • The "HealthKit" capability on the Watch App target.
//   • An NSHealthShareUsageDescription string in the target's Info.
//

import Foundation
import HealthKit

@MainActor
final class HealthManager: ObservableObject {

    private let store = HKHealthStore()

    @Published var authorized = false
    @Published var lastSyncSummary: String = ""

    static var isAvailable: Bool { HKHealthStore.isHealthDataAvailable() }

    private var readTypes: Set<HKObjectType> {
        var set = Set<HKObjectType>()
        if let steps  = HKQuantityType.quantityType(forIdentifier: .stepCount)            { set.insert(steps) }
        if let dist   = HKQuantityType.quantityType(forIdentifier: .distanceWalkingRunning) { set.insert(dist) }
        if let energy = HKQuantityType.quantityType(forIdentifier: .activeEnergyBurned)   { set.insert(energy) }
        return set
    }

    func requestAuthorization() async {
        guard Self.isAvailable else { return }
        do {
            try await store.requestAuthorization(toShare: [], read: readTypes)
            authorized = true
        } catch {
            authorized = false
        }
    }

    /// Cumulative total of a quantity type since the start of today.
    private func todayTotal(_ id: HKQuantityTypeIdentifier, unit: HKUnit) async -> Double {
        guard let type = HKQuantityType.quantityType(forIdentifier: id) else { return 0 }
        let start = Calendar.current.startOfDay(for: Date())
        let predicate = HKQuery.predicateForSamples(withStart: start, end: Date(), options: .strictStartDate)

        return await withCheckedContinuation { continuation in
            let query = HKStatisticsQuery(quantityType: type,
                                          quantitySamplePredicate: predicate,
                                          options: .cumulativeSum) { _, stats, _ in
                let value = stats?.sumQuantity()?.doubleValue(for: unit) ?? 0
                continuation.resume(returning: value)
            }
            store.execute(query)
        }
    }

    /// Today's value for a given metric, in the metric's natural unit.
    func value(for metric: HealthMetric) async -> Double {
        switch metric {
        case .steps:        return await todayTotal(.stepCount, unit: .count())
        case .distanceKm:   return await todayTotal(.distanceWalkingRunning, unit: .meterUnit(with: .kilo))
        case .activeEnergy: return await todayTotal(.activeEnergyBurned, unit: .kilocalorie())
        }
    }
}
