//
//  NotificationManager.swift
//  The System
//
//  Local notifications styled as System warnings: a daily "clear your quest"
//  reminder, plus an instant alert when the Penalty Zone triggers.
//

import Foundation
import UserNotifications

enum NotificationManager {

    static let reminderID = "daily_quest_reminder"

    /// Ask once for permission to post alerts/sounds.
    static func requestAuthorization() {
        UNUserNotificationCenter.current()
            .requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    /// Schedule a repeating daily reminder at the given time.
    static func scheduleDailyReminder(hour: Int, minute: Int = 0) {
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers: [reminderID])

        let content = UNMutableNotificationContent()
        content.title = "⚠️ DAILY QUEST"
        content.body  = "Hunter, your Daily Quest is incomplete. Clear it or enter the Penalty Zone."
        content.sound = .default

        var time = DateComponents()
        time.hour = hour
        time.minute = minute

        let trigger = UNCalendarNotificationTrigger(dateMatching: time, repeats: true)
        let request = UNNotificationRequest(identifier: reminderID, content: content, trigger: trigger)
        center.add(request)
    }

    static func cancelDailyReminder() {
        UNUserNotificationCenter.current()
            .removePendingNotificationRequests(withIdentifiers: [reminderID])
    }

    /// Fire an immediate System alert (used when the Penalty Zone triggers).
    static func notify(title: String, body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body  = body
        content.sound = .default

        let request = UNNotificationRequest(identifier: UUID().uuidString,
                                            content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
