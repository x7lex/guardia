"use client"

import { useId, useState } from "react"

export type GeminiFinding = {
    path: string
    status: "waiting" | "loading" | "complete" | "error"
    review?: string
    model?: string
    error?: string
}

export default function GeminiSummary({ findings, onRetry }: {
    findings: GeminiFinding[]
    onRetry: (path: string) => void
}) {
    const id = useId()
    const [selectedPath, setSelectedPath] = useState("")
    const [expanded, setExpanded] = useState(true)
    const selected = findings.find(item => item.path === selectedPath) ?? findings[0]
    const completed = findings.filter(item => item.status === "complete").length
    if (!selected) return null

    return (
        <section className="border-b-2 border-[#cbaa9c] bg-[#fff9e6] px-4 py-3 text-[#4a2b45]" aria-label="Gemini scan findings">
            <div className="mx-auto max-w-4xl">
                <div className="flex flex-wrap items-center justify-between gap-2">
                    <h2 className="text-sm font-bold">Gemini · Behavior review</h2>
                    <div className="flex items-center gap-3 text-xs">
                        <span role="status">{completed} of {findings.length} reviewed</span>
                        <button type="button" className="retro-button px-3" aria-expanded={expanded} aria-controls={id} onClick={() => setExpanded(value => !value)}>
                            {expanded ? "Collapse" : "Show findings"}
                        </button>
                    </div>
                </div>
                <div id={id} hidden={!expanded}>
                    <label className="mt-2 flex min-w-0 items-center gap-2 text-xs">
                        <span>File</span>
                        <select className="retro-input-frame min-w-0 flex-1 px-2 py-1" value={selected.path} onChange={event => setSelectedPath(event.target.value)}>
                            {findings.map(item => <option key={item.path} value={item.path}>{item.path} · {item.status === "complete" ? "Reviewed" : item.status === "error" ? "Review unavailable" : item.status === "loading" ? "Reviewing…" : "Waiting"}</option>)}
                        </select>
                    </label>
                    <div className="mt-2 max-h-[24vh] overflow-y-auto text-sm" aria-live="polite">
                        {(selected.status === "loading" || selected.status === "waiting") && <p role="status">{selected.status === "loading" ? "Gemini is reviewing the detected behaviors and scan evidence…" : "Waiting for Gemini review…"}</p>}
                        {selected.status === "error" && <div role="alert"><p>{selected.error}</p><button type="button" className="retro-button mt-2 px-3" onClick={() => onRetry(selected.path)}>Retry review</button></div>}
                        {selected.status === "complete" && <><p className="whitespace-pre-wrap break-words leading-relaxed">{selected.review}</p><p className="mt-2 text-xs text-[#805775]">{selected.model} · AI interpretation of the scan evidence.</p></>}
                    </div>
                </div>
            </div>
        </section>
    )
}
