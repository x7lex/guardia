import type { Report } from "../components/report-marker";

export function scanTranscript(scan: {
  path: string;
  scannedAt: string;
  reports: Record<string, Report>;
  issues?: { file: string; reason: string }[];
}) {
  const lines = [
    "GUARDIA — SCAN TRANSCRIPT",
    `Folder: ${scan.path}`,
    `Scanned: ${scan.scannedAt}`,
    `Files: ${Object.keys(scan.reports).length}`,
    "",
  ];
  function describe(value: unknown, indent = ""): void {
    if (Array.isArray(value)) {
      if (!value.length) lines.push(`${indent}(none)`);
      value.forEach((item, index) => {
        if (item !== null && typeof item === "object") {
          lines.push(`${indent}${index + 1}.`);
          describe(item, indent + "  ");
        } else lines.push(`${indent}- ${String(item)}`);
      });
    } else if (value !== null && typeof value === "object") {
      Object.entries(value).forEach(([key, item]) => {
        const label = key.replaceAll("_", " ");
        if (item !== null && typeof item === "object") {
          lines.push(`${indent}${label}:`);
          describe(item, indent + "  ");
        } else
          lines.push(`${indent}${label}: ${String(item ?? "Not available")}`);
      });
    }
  }
  for (const [path, report] of Object.entries(scan.reports)) {
    lines.push(
      "=".repeat(60),
      `FILE: ${path}`,
      `RESULT: ${report.risk_assessment.risk.verdict ?? report.risk_assessment.risk.level} · ${report.risk_assessment.risk.points}/10 triage score`,
      "",
    );
    describe(report);
    lines.push("");
  }
  for (const issue of scan.issues ?? [])
    lines.push(`SKIPPED: ${issue.file} — ${issue.reason}`);
  return lines.join("\n") + "\n";
}
