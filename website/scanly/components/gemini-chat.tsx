"use client"

import { useEffect, useRef, useState } from "react"
import type { Report } from "./report-marker"
import type { GeminiFinding } from "./gemini-summary"
import { isGeminiResult } from "@/lib/gemini-review"

type Message = { role: "user" | "model"; text: string }
type Conversation = { messages: Message[]; draft: string; busy: boolean; error: string }
const empty: Conversation = { messages: [], draft: "", busy: false, error: "" }

export function Sparkles() {
    return <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="m14 2 2.6 6.4L23 11l-6.4 2.6L14 20l-2.6-6.4L5 11l6.4-2.6L14 2ZM5 1l1.2 3L9 5 6.2 6.2 5 9 3.8 6.2 1 5l2.8-1L5 1Zm0 14 1.2 3L9 19l-2.8 1.2L5 23l-1.2-2.8L1 19l2.8-1L5 15Z" /></svg>
}

export default function GeminiChat({ open, onClose, reports, findings, onRetry }: {
    open: boolean; onClose: () => void; reports: Record<string, Report>
    findings: GeminiFinding[]; onRetry: (path: string) => void
}) {
    const [selectedPath, setSelectedPath] = useState("")
    const [conversations, setConversations] = useState(new Map<Report, Conversation>())
    const [position, setPosition] = useState({ x: 24, y: 120 })
    const panel = useRef<HTMLElement>(null)
    const input = useRef<HTMLTextAreaElement>(null)
    const end = useRef<HTMLDivElement>(null)
    const drag = useRef<{ x: number; y: number } | null>(null)
    const requests = useRef(new Map<Report, AbortController>())
    const selected = findings.find(item => item.path === selectedPath) ?? findings[0]
    const report = selected ? reports[selected.path] : undefined
    const chat = report ? conversations.get(report) ?? empty : empty

    function update(target: Report, patch: Partial<Conversation>) {
        setConversations(current => new Map(current).set(target, { ...(current.get(target) ?? empty), ...patch }))
    }
    function clamp(x: number, y: number) {
        const rect = panel.current?.getBoundingClientRect()
        return { x: Math.max(0, Math.min(x, window.innerWidth - (rect?.width ?? 400))), y: Math.max(0, Math.min(y, window.innerHeight - (rect?.height ?? 400))) }
    }
    useEffect(() => {
        if (!open) return
        input.current?.focus()
        function resize() { setPosition(current => clamp(current.x, current.y)) }
        resize()
        window.addEventListener("resize", resize)
        return () => window.removeEventListener("resize", resize)
    }, [open])
    useEffect(() => { if (open) end.current?.scrollIntoView({ block: "nearest" }) }, [chat.messages, chat.busy, open, selectedPath])
    useEffect(() => {
        const active = requests.current
        return () => { active.forEach(controller => controller.abort()) }
    }, [])

    async function send() {
        if (!report || !chat.draft.trim() || requests.current.has(report)) return
        const target = report
        const question = chat.draft.trim()
        // Keep recent complete turns; always begin with a user message.
        const messages: Message[] = [...chat.messages.slice(-38), { role: "user", text: question }]
        const controller = new AbortController()
        requests.current.set(target, controller)
        update(target, { busy: true, error: "", draft: "", messages: [...chat.messages, { role: "user", text: question }] })
        try {
            const response = await fetch("/api/chat", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ...target, gemini_review: selected?.review ? { review: selected.review, model: selected.model } : target.gemini_review, chat_messages: messages }),
                signal: AbortSignal.any([controller.signal, AbortSignal.timeout(100_000)]),
            })
            const result = await response.json()
            if (!response.ok) throw new Error(typeof result?.detail === "string" ? result.detail : "Could not send your message.")
            if (!isGeminiResult(result)) throw new Error("Gemini returned an incomplete answer. Please try again.")
            update(target, { messages: [...chat.messages, { role: "user", text: question }, { role: "model", text: result.review }] })
        } catch (error) {
            update(target, { messages: chat.messages, draft: question, error: controller.signal.aborted ? "Reply stopped. Your question is ready to resend." : error instanceof Error ? error.message : "Could not get a reply." })
        } finally {
            requests.current.delete(target)
            update(target, { busy: false })
        }
    }

    return <section ref={panel} id="gemini-chat" role="dialog" aria-modal="false" aria-label="Gemini AI chat" hidden={!open}
        className="fixed z-[100] flex h-[min(600px,calc(100dvh-16px))] w-[min(480px,calc(100vw-16px))] flex-col border-2 border-[#70535f] bg-[#fff9e6] p-1 text-[#4a2b45] shadow-xl"
        style={{ left: position.x, top: position.y, display: open ? "flex" : "none" }}
        onKeyDown={event => { if (event.key === "Escape") { event.stopPropagation(); onClose() } }}>
        <div className="retro-window-title touch-none select-none" onPointerDown={event => {
            if ((event.target as HTMLElement).closest("button")) return
            drag.current = { x: event.clientX - position.x, y: event.clientY - position.y }
            event.currentTarget.setPointerCapture(event.pointerId)
        }} onPointerMove={event => { if (drag.current) setPosition(clamp(event.clientX - drag.current.x, event.clientY - drag.current.y)) }}
            onPointerUp={() => { drag.current = null }} onPointerCancel={() => { drag.current = null }} style={{ cursor: "move" }}>
            <span className="flex items-center gap-2"><Sparkles />Gemini · Ask about your scan</span>
            <button type="button" className="retro-window-control" aria-label="Close Gemini chat" onClick={onClose}>×</button>
        </div>
        {!selected ? <p className="p-4 text-sm">Scan a file or open a past scan to review its findings and ask Gemini questions.</p> : <>
            <label className="flex items-center gap-2 p-3 text-xs">File
                <select className="retro-input-frame min-w-0 flex-1 p-2" value={selected.path} onChange={event => setSelectedPath(event.target.value)}>
                    {findings.map(item => <option key={item.path} value={item.path}>{item.path}</option>)}
                </select>
            </label>
            <div className="min-h-0 flex-1 overflow-y-auto px-3 pb-3 text-sm" role="log" aria-label="Conversation">
                <div className="mb-3 border border-[#cbaa9c] bg-[#fffdf5] p-3">
                    <p className="mb-2 text-xs font-bold text-[#805775]">GEMINI · SCAN REVIEW</p>
                    {selected.status === "complete" ? <p className="whitespace-pre-wrap break-words">{selected.review}</p> : selected.status === "error" ? <><p role="alert">{selected.error}</p><button className="retro-button mt-2 px-3" onClick={() => onRetry(selected.path)}>Retry review</button></> : <p role="status">Reviewing scan evidence…</p>}
                </div>
                {chat.messages.map((message, index) => <div key={index} className={`mb-3 border border-[#cbaa9c] p-3 ${message.role === "user" ? "ml-8 bg-[#eadfcf]" : "mr-3 bg-[#fffdf5]"}`}><p className="mb-1 text-xs font-bold text-[#805775]">{message.role === "user" ? "YOU" : "GEMINI"}</p><p className="whitespace-pre-wrap break-words">{message.text}</p></div>)}
                {chat.busy && <p role="status">Gemini is thinking…</p>}
                {chat.error && <p role="alert" className="text-[#b32635]">{chat.error}</p>}
                <div ref={end} />
            </div>
            <form className="border-t border-[#cbaa9c] p-3" onSubmit={event => { event.preventDefault(); void send() }}>
                <label htmlFor="gemini-question" className="sr-only">Ask Gemini about this file</label>
                <textarea ref={input} id="gemini-question" rows={2} maxLength={12000} disabled={chat.busy} value={chat.draft} onChange={event => { if (report) update(report, { draft: event.target.value }) }}
                    onKeyDown={event => { if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) { event.preventDefault(); void send() } }}
                    placeholder="Why was this flagged? What should I do next?" className="retro-input-frame w-full resize-none p-2 text-sm" />
                <div className="mt-2 flex items-center justify-between gap-2"><span className="text-[11px] text-[#805775]">Answers use this file’s scan evidence.</span>{chat.busy ? <button type="button" className="retro-button px-3" onClick={() => { if (report) requests.current.get(report)?.abort() }}>Stop</button> : <button className="retro-button flex items-center gap-2 px-4" disabled={!chat.draft.trim()}><Sparkles />Send</button>}</div>
            </form>
        </>}
    </section>
}
