"use client"

import { useId, useRef, useState, type DragEvent } from "react"

interface DragBoxProps {
    onDrop: (absolutePath: string) => void
    disabled?: boolean
    className?: string
}

export default function DragBox({ onDrop, disabled = false, className = "" }: DragBoxProps) {
    const [dragging, setDragging] = useState(false)
    const [notice, setNotice] = useState("")
    const depth = useRef(0)
    const noticeId = useId()

    function handleDrop(event: DragEvent<HTMLDivElement>) {
        event.preventDefault()
        event.stopPropagation()
        depth.current = 0
        setDragging(false)
        if (disabled) return
        setNotice("")

        const files = event.dataTransfer.files
        if (files.length !== 1) {
            setNotice("Drop one file or folder at a time.")
            return
        }
        if (!window.electronAPI?.getPathForFile) {
            setNotice("Absolute paths are available in the desktop app. In the browser, paste the full path into the field below.")
            return
        }

        let path: string
        try {
            path = window.electronAPI.getPathForFile(files[0])
        } catch {
            setNotice("Could not read this path. Try dropping it again or paste the full path below.")
            return
        }
        if (!path) {
            setNotice("This item has no local file path. Drop a file or folder from your computer.")
            return
        }
        onDrop(path)
        setNotice(`Selected: ${path}`)
    }

    return (
        <div
            role="region"
            aria-label="Drop a file or folder"
            aria-describedby={noticeId}
            onDragEnter={event => {
                event.preventDefault()
                if (disabled) return
                depth.current += 1
                setDragging(true)
            }}
            onDragOver={event => {
                event.preventDefault()
                event.dataTransfer.dropEffect = disabled ? "none" : "copy"
            }}
            onDragLeave={event => {
                event.preventDefault()
                depth.current = Math.max(0, depth.current - 1)
                if (depth.current === 0) setDragging(false)
            }}
            onDrop={handleDrop}
            className={`border-2 border-dashed p-6 text-center text-sm ${dragging && !disabled ? "border-[#6b2d63] bg-[#ffe1bf]" : "border-[#cbaa9c] bg-[#fffdf5]"} ${disabled ? "opacity-50" : ""} ${className}`}
        >
            <p>{disabled ? "Wait for the scan to finish." : "Drop a file or folder here"}</p>
            <p id={noticeId} role="status" className="mt-2 break-all text-xs text-[#805775]">
                {notice || "Desktop app only. You can also enter a path below."}
            </p>
        </div>
    )
}
