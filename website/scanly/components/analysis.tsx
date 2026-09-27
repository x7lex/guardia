"use client"

import { useState } from "react"

interface AnalysisProps {
    path: string
    className?: string
    setReport: (report: string) => void
}

export default function Analysis({ path, className, setReport }: AnalysisProps) {
    const [scanning, setScanning] = useState(false)
    const [error, setError] = useState("")

    function sendPath() {
        if (!path || scanning) return
        setScanning(true)
        setError("")
        const ws = new WebSocket("ws://localhost:8000/path")
        let received = false
        ws.onopen = () => ws.send(JSON.stringify({ path }))
        ws.onmessage = (event) => {
            received = true
            setReport(event.data)
            setScanning(false)
            ws.close()
        }
        ws.onerror = () => {
            setError("Could not connect. Check the scanner and try again.")
            setScanning(false)
        }
        ws.onclose = () => {
            setScanning(false)
            if (!received) setError("Scan interrupted. Check the scanner and try again.")
        }
    }

    return (
        <div className={`flex flex-col gap-2 ${className ?? ""}`}>
            <button
                type="button"
                onClick={sendPath}
                disabled={!path || scanning}
                className="retro-button min-h-11 px-6 py-2.5"
            >
                {scanning ? "Scanning…" : "Scan folder"}
            </button>
            {error && <p role="alert" className="max-w-48 text-xs text-[#b32635]">{error}</p>}
        </div>
    )
}
