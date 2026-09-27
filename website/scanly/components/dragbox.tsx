"use client"

import { useId, useRef, useState, type DragEvent } from "react"

interface DragBoxProps {
    onDrop: (absolutePath: string) => void
    onFilesSelected?: (files: File[]) => void
    disabled?: boolean
    className?: string
}

async function readEntry(entry: FileSystemEntry): Promise<File[]> {
    if (entry.isFile) {
        const file = await new Promise<File>((resolve, reject) => (entry as FileSystemFileEntry).file(resolve, reject))
        Object.defineProperty(file, "webkitRelativePath", { value: entry.fullPath.replace(/^\//, "") })
        return [file]
    }
    const reader = (entry as FileSystemDirectoryEntry).createReader()
    const files: File[] = []
    while (true) {
        const entries = await new Promise<FileSystemEntry[]>((resolve, reject) => reader.readEntries(resolve, reject))
        if (!entries.length) break
        for (const child of entries) files.push(...await readEntry(child))
    }
    return files
}

export default function DragBox({ onDrop, onFilesSelected, disabled = false, className = "" }: DragBoxProps) {
    const [dragging, setDragging] = useState(false)
    const [notice, setNotice] = useState("")
    const depth = useRef(0)
    const noticeId = useId()
    const [reading, setReading] = useState(false)

    async function handleDrop(event: DragEvent<HTMLDivElement>) {
        event.preventDefault()
        event.stopPropagation()
        depth.current = 0
        setDragging(false)
        if (disabled || reading) return
        setNotice("")

        const files = Array.from(event.dataTransfer.files)
        // Capture entries before awaiting: the browser clears drag data after this event.
        const entries = Array.from(event.dataTransfer.items).map(item => item.webkitGetAsEntry()).filter((entry): entry is FileSystemEntry => entry !== null)
        if (onFilesSelected) {
            setReading(true)
            try {
                const selected: File[] = []
                if (entries.length) {
                    for (const entry of entries) selected.push(...await readEntry(entry))
                } else selected.push(...files)
                if (!selected.length) { setNotice("No files found in this drop."); return }
                if (files[0] && window.electronAPI?.getPathForFile) {
                    const path = window.electronAPI.getPathForFile(files[0])
                    if (path) onDrop(path)
                }
                onFilesSelected(selected)
                setNotice(`${selected.length} files selected.`)
            } catch {
                setNotice("Could not read the dropped files. Try Browse folder or Choose files.")
            } finally { setReading(false) }
            return
        }
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
            <p>{disabled ? "Wait for the scan to finish." : reading ? "Reading folder…" : "Drop a file or folder here"}</p>
            <p id={noticeId} role="status" className="mt-2 break-all text-xs text-[#805775]">
                {notice || (onFilesSelected ? "Or use Browse folder / Choose files above." : "Desktop app only. You can also enter a path below.")}
            </p>
        </div>
    )
}
