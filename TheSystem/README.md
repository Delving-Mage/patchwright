# ⚔️ The System — A Solo Leveling Life RPG for Apple Watch

> *"You have acquired the qualifications to become a Player. Will you accept?"*

Turn real life into the System from **Solo Leveling**, right on your wrist.
Glowing blue holographic windows, daily quests, a penalty zone, leveling,
attribute points, ranks, job changes, and a shadow army.

This folder contains the **complete watchOS app source** (SwiftUI). It can't
be compiled on Linux — Apple Watch apps require **a Mac with Xcode** — so the
code is ready for you to drop into an Xcode project and run.

---

## ✨ Features

| Feature | What it does |
|---|---|
| 🔵 **Status window** | Name, Rank (E→S→Monarch), Level, Job, EXP bar, Power, Fatigue, Streak |
| 📜 **Daily Quests** | Push-ups / sit-ups / squats / run / study by default. Add your own. |
| ⚠️ **Penalty Zone** | Miss a day's quests → streak resets, fatigue +30, EXP lost |
| 📈 **Leveling + Stats** | Earn EXP, level up, spend points on STR / AGI / VIT / INT / PER |
| 🎖️ **Ranks + Jobs** | Auto rank by level; unlock Fighter → … → **Shadow Monarch** |
| 👤 **Shadow Army** | Clear a **Boss Quest** to "Arise" a shadow soldier (collectible rewards) |
| 🔔 **System Alerts** | Optional daily reminder notification + an instant Penalty alert |
| ❤️ **Health Sync** | Auto-clears the Run / Steps quests from real HealthKit activity |
| 💾 **Saves locally** | Everything persists on the watch via `UserDefaults` |

All progress resets/grades automatically at the start of each new day.

---

## 🛠️ How to build & run on your Apple Watch

You need: a **Mac**, **Xcode 15+**, an **iPhone** paired with your **Apple
Watch**, and a free **Apple ID** (no paid developer account required for
personal use).

### 1. Create the project in Xcode
1. Open **Xcode → File → New → Project**.
2. Choose the **watchOS** tab → **App** → Next.
3. Product Name: `The System`. Interface: **SwiftUI**. Language: **Swift**.
   Leave "Watch App for iOS App" *off* (a standalone watch app is fine).
4. Pick a save location and create it.

### 2. Add the source files
1. Delete the auto-generated `ContentView.swift` and `*App.swift` from the
   new project (move to Trash).
2. Drag **all `.swift` files from this `Source/` folder** into the Xcode
   project navigator (into the Watch App target).
3. When prompted, check **"Copy items if needed"** and make sure the
   **Watch App target** is selected under "Add to targets".

> The files: `TheSystemApp.swift`, `Models.swift`, `SystemStore.swift`,
> `Theme.swift`, `StatusView.swift`, `QuestsView.swift`, `StatsView.swift`,
> `ShadowsView.swift`, `SettingsView.swift`, `Notifications.swift`,
> `HealthManager.swift`, `NotificationManager.swift`.

### 2b. Enable Health & Notifications (one-time capability setup)
The Health Sync and reminder features need two permissions wired up in Xcode:

1. Select the project → the **Watch App target** → **Signing & Capabilities**
   → **+ Capability** → add **HealthKit**.
2. Still on the target → **Info** tab → add this key:
   - **Privacy - Health Share Usage Description**
     (`NSHealthShareUsageDescription`) →
     *"The System reads your activity to auto-clear movement quests."*
3. Notifications need no capability — the app requests permission the first
   time you enable the reminder in **Settings**.

> Skipping this step is fine — the app still runs; only the Health Sync button
> and reminders will be inactive.

### 3. Run in the simulator (instant)
1. In the toolbar, pick a **Watch simulator** (e.g. *Apple Watch Series 10*).
2. Press **▶︎ Run**. The blue System windows should appear — swipe up/down
   to move between Status / Quests / Stats / Shadows.

### 4. Install on your real watch
1. Connect your **iPhone** to the Mac (the paired watch comes along).
2. Xcode → **Signing & Capabilities** → set **Team** to your Apple ID
   (add it under Xcode → Settings → Accounts if needed). Xcode will pick a
   unique bundle id automatically.
3. Select your **physical watch** as the run destination and press **▶︎ Run**.
4. On the watch, you may need **Settings → General → VPN & Device Management**
   → trust your developer certificate the first time.

> With a free Apple ID the app re-signs every 7 days (just re-run from Xcode).
> A paid Apple Developer account ($99/yr) removes that limit.

---

## 🎮 Quick usage

- **Swipe up/down** to move between the four screens.
- Tap a quest to **clear** it (grants EXP + a stat). Clear them all daily to
  build your **streak** and avoid the **Penalty Zone**.
- Add custom quests with **+ Add Quest**. Toggle **Boss Quest** to earn a
  **Shadow** on completion.
- Spend points on the **Stats** screen, and **change your job** as you level.

---

## ⚙️ Tuning the game

All the rules live in `SystemStore.swift`:

- **`xpToNext`** — the leveling curve (`100 × level^1.4`).
- **`addXP` / stat points** — `+3` points per level.
- **`triggerPenalty`** — what failing a day costs.
- **`Rank.forLevel`** (in `Models.swift`) — level → rank thresholds.
- **`JobCatalog`** — classes and their unlock levels.
- **`Quest.defaultDailies`** — your starting quest list.

---

## 🚀 Ideas for v2
- iCloud sync + an iPhone companion app with a bigger status window.
- Haptics on Level Up / Penalty for full drama.
- A weekly auto-generated **Boss Quest** for guaranteed shadow drops.

*(Done: ✅ local reminder notifications, ✅ HealthKit auto-clear.)*

Happy leveling, Hunter. 🗡️
