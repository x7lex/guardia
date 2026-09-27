import type { Report } from "../components/report-marker";

export const MAX_FILE_BYTES = 512 * 1024 * 1024;
export type ScanIssue = { file: string; reason: string };
export type ScanResult =
  | { status: "scanned"; file: string; report: Report }
  | { status: "skipped"; file: string; reason: string };

export async function scanFile(
  file: File,
  signal: AbortSignal,
): Promise<ScanResult> {
  const name = file.webkitRelativePath || file.name;
  if (file.size > MAX_FILE_BYTES)
    return {
      status: "skipped",
      file: name,
      reason: "File exceeds the 512 MiB scan limit",
    };
  const response = await fetch(`/api/scan?name=${encodeURIComponent(name)}`, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: file,
    signal,
  });
  const result = await response.json().catch(() => null);
  if (!response.ok)
    throw new Error(
      typeof result?.detail === "string"
        ? result.detail
        : `Scan failed (${response.status})`,
    );
  if (result?.status === "skipped" && typeof result.reason === "string")
    return result;
  if (
    result?.status !== "scanned" ||
    !result.report?.analysis?.file ||
    !result.report?.risk_assessment?.risk
  ) {
    throw new Error("The scanner returned an invalid report");
  }
  return result;
}
