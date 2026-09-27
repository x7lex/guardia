// Include legacy labels so reports already saved in this browser still filter correctly.
export function riskZone(level: string): "safe" | "review" | "unsafe" {
    const normalized = level.trim().toLowerCase()
    if (["safe", "low", "no indicators detected", "low risk"].includes(normalized)) return "safe"
    if (["unsafe", "high", "critical", "high risk", "dangerous"].includes(normalized)) return "unsafe"
    return "review"
}
