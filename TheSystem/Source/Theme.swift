//
//  Theme.swift
//  The System
//
//  The Solo Leveling "blue holographic window" look, plus reusable pieces.
//

import SwiftUI

enum SystemTheme {
    static let bg          = Color.black
    static let panelFill   = Color(red: 0.02, green: 0.07, blue: 0.14).opacity(0.88)
    static let accent      = Color(red: 0.30, green: 0.78, blue: 1.00)   // System blue
    static let accentBright = Color(red: 0.55, green: 0.93, blue: 1.00)  // glowing edge
    static let danger      = Color(red: 1.00, green: 0.27, blue: 0.36)
    static let gold        = Color(red: 1.00, green: 0.82, blue: 0.35)

    static let mono = Font.system(.body, design: .monospaced)
}

// MARK: - SystemPanel

/// The signature framed, glowing blue "window" the System uses for every
/// notification. Wrap any content in it.
struct SystemPanel<Content: View>: View {
    var header: String? = nil
    var tint: Color = SystemTheme.accent
    @ViewBuilder var content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let header {
                HStack(spacing: 4) {
                    Image(systemName: "diamond.fill")
                        .font(.system(size: 5))
                    Text(header)
                        .font(.system(.caption2, design: .monospaced).weight(.bold))
                        .tracking(2)
                }
                .foregroundStyle(SystemTheme.accentBright)
            }
            content()
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(SystemTheme.panelFill)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(tint.opacity(0.85), lineWidth: 1)
        )
        .shadow(color: tint.opacity(0.45), radius: 6)
    }
}

// MARK: - Progress bar

struct SystemBar: View {
    var value: Int
    var max: Int
    var tint: Color = SystemTheme.accent

    private var fraction: CGFloat {
        guard max > 0 else { return 0 }
        return CGFloat(min(1, Swift.max(0, Double(value) / Double(max))))
    }

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.white.opacity(0.08))
                Capsule()
                    .fill(LinearGradient(colors: [tint, SystemTheme.accentBright],
                                         startPoint: .leading, endPoint: .trailing))
                    .frame(width: geo.size.width * fraction)
                    .shadow(color: tint.opacity(0.8), radius: 4)
            }
        }
        .frame(height: 6)
    }
}

// MARK: - Rank badge

struct RankBadge: View {
    let rank: Rank

    var body: some View {
        Text(rank == .monarch ? "M" : rank.rawValue)
            .font(.system(.title3, design: .monospaced).weight(.black))
            .foregroundStyle(rank.color)
            .frame(width: 34, height: 34)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(rank.color.opacity(0.12))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .stroke(rank.color, lineWidth: 1.5)
            )
            .shadow(color: rank.color.opacity(0.7), radius: 5)
    }
}

// MARK: - Small helpers

struct StatRow: View {
    let label: String
    let value: String
    var icon: String? = nil
    var tint: Color = SystemTheme.accentBright

    var body: some View {
        HStack(spacing: 6) {
            if let icon {
                Image(systemName: icon)
                    .font(.system(size: 11))
                    .foregroundStyle(tint)
                    .frame(width: 16)
            }
            Text(label)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.white.opacity(0.8))
            Spacer()
            Text(value)
                .font(.system(.caption, design: .monospaced).weight(.bold))
                .foregroundStyle(.white)
        }
    }
}

/// A reusable dark, blue-bordered background for full screens.
struct SystemBackground: View {
    var body: some View {
        ZStack {
            SystemTheme.bg
            RadialGradient(
                colors: [SystemTheme.accent.opacity(0.18), .clear],
                center: .top, startRadius: 0, endRadius: 260
            )
        }
        .ignoresSafeArea()
    }
}
