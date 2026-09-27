// Include legacy labels so reports already saved in this browser still filter correctly.
export function riskZone(
  level: string,
  points?: number,
): "safe" | "review" | "unsafe" {
  if (typeof points === "number" && Number.isFinite(points)) {
    return points < 3 ? "safe" : points < 5 ? "review" : "unsafe";
  }
  const normalized = level.trim().toLowerCase();
  if (
    ["safe", "low", "no indicators detected", "low risk"].includes(normalized)
  )
    return "safe";
  if (
    ["unsafe", "high", "critical", "high risk", "dangerous"].includes(
      normalized,
    )
  )
    return "unsafe";
  return "review";
}
