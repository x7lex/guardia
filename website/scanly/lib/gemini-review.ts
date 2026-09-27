export type GeminiResult = { review: string; model: string }

export async function requestGeminiReview(report: object): Promise<GeminiResult> {
    const response = await fetch("/api/review", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(report), signal: AbortSignal.timeout(100_000),
    })
    const body: unknown = await response.json().catch(() => null)
    if (!response.ok) {
        const detail = body && typeof body === "object" && "detail" in body ? body.detail : null
        throw new Error(typeof detail === "string" ? detail : `Gemini review failed (${response.status}).`)
    }
    if (!isGeminiResult(body)) throw new Error("Gemini returned an invalid review. Please try again.")
    return body
}

export function isGeminiResult(value: unknown): value is GeminiResult {
    if (!value || typeof value !== "object") return false
    const result = value as Partial<GeminiResult>
    return typeof result.review === "string" && Boolean(result.review.trim()) && typeof result.model === "string"
}

// Keep one request in flight, even when multiple folders finish together.
// Cache by report object so reopening a result never submits it twice.
export function createReviewQueue<T extends { gemini_review?: GeminiResult }>(request: (report: T) => Promise<GeminiResult>) {
    const requests = new WeakMap<T, Promise<GeminiResult>>()
    let tail: Promise<unknown> = Promise.resolve()
    return (report: T, onStart: () => void = () => {}, retry = false): Promise<GeminiResult> => {
        if (isGeminiResult(report.gemini_review)) return Promise.resolve(report.gemini_review)
        if (!retry && requests.has(report)) return requests.get(report)!
        const pending = tail.then(async () => {
            onStart()
            return request(report)
        })
        requests.set(report, pending)
        // A failed file must not prevent later files from being reviewed.
        tail = pending.catch(() => {})
        return pending
    }
}
