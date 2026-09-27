"use client"

import { useId, useState } from "react"

declare global {
    interface Window {
        electronAPI?: { selectFolders: () => Promise<string[]> }
    }
}

export default function FolderPicker({ path, onPathChange, onFoldersSelected, disabled = false }: {
    path: string
    onPathChange: (path: string) => void
    onFoldersSelected?: (paths: string[]) => void
    disabled?: boolean
}) {
    const id = useId()
    const [notice, setNotice] = useState("")
    async function browse() {
        if (!window.electronAPI?.selectFolders) {
            setNotice("In the browser, paste the full folder path below. Folder browsing is available in the desktop app.")
            return
        }
        try {
            const paths = await window.electronAPI.selectFolders()
            if (paths.length) {
                if (onFoldersSelected) onFoldersSelected(paths)
                else onPathChange(paths[0])
                setNotice("")
            }
        } catch {
            setNotice("Could not open the folder picker. You can paste the full path instead.")
        }
    }
    return (
        <div className="flex w-full flex-col gap-2">
            <label htmlFor={id} className="text-xs font-bold text-[#6b2d63]">Folder path</label>
            <div className="retro-input-frame flex min-w-0">
                <input id={id} type="text" value={path} disabled={disabled} onChange={event => onPathChange(event.target.value)} placeholder="/Users/you/Documents/folder" className="min-w-0 flex-1 px-3 py-2.5 text-sm outline-none" />
                <button type="button" disabled={disabled} onClick={browse} className="retro-button px-3">Browse…</button>
            </div>
            {notice && <p role="status" className="text-xs text-[#805775]">{notice}</p>}
        </div>
    )
}
