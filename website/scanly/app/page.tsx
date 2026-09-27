"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { scanTranscript } from "@/lib/scan-transcript"
import Settings from "@/components/settings"
import { playRetroSound } from "@/lib/retro-sounds"
import { reportMatches, RiskFilter } from "@/lib/report-view"
import RetroIcon from "@/components/retro-icon"
import Banner from "@/components/banner"
import Form from "@/components/Form"
import FolderPicker from "@/components/FolderPicker"
import ReportMarker, { Report, riskAppearance } from "@/components/report-marker"
import ReportDetailModal from "@/components/report-detail-modal"
import { Body, Size, Zone, keepInside, zoneCenter, zoneScale, separate } from "@/lib/marker-physics"

type ReportMap = Record<string, Report>
type Visit = { path: string; reports: ReportMap | null; scanId?: string; paths?: string[] }
type SavedScan = { id: string; scannedAt: string; path: string; reports: ReportMap }
// Retain the original storage key so existing saved scans remain available.
const SCAN_STORAGE_KEY = "scanly.past-scans.v1"

type BatchFolder = { path: string; status: "waiting" | "scanning" | "complete" | "failed" | "stopped"; scan?: SavedScan }

type Marker = Body & { id: string; report: Report; zone: Zone; scale: number }
const reportZone = (report: Report): Zone => riskAppearance(report.risk_assessment.risk.level).label.toLowerCase() as Zone

function createMarkers(reports: ReportMap | null, width: number, top: number, height: number): Marker[] {
    const entries = Object.entries(reports ?? {})
    const nextMarkers: Marker[] = []
    const availableHeight = Math.max(1, height - top)
    const useCompact = entries.length * 250 * 180 / (width * availableHeight) > 0.38
    const cardWidth = useCompact ? 180 : 250
    const cardHeight = useCompact ? 72 : 180
    for (const [id, report] of entries) {
      const zone = reportZone(report)
      const center = zoneCenter(zone, width, top, height)
      const spreadX = Math.max(0, width / 6 - cardWidth / 2 - 12)
      const minY = Math.min(height - cardHeight / 2, top + 72 + cardHeight / 2)
      const maxY = Math.max(minY, height - cardHeight / 2 - 16)
      let position = { x: center.x, y: (minY + maxY) / 2 }
      let bestClearance = -Infinity
      // Random candidates with generous initial spacing, not a repeating grid.
      // This affects placement only; collision contacts still have no padding.
      for (let attempt = 0; attempt < 80; attempt++) {
        const candidate = {
          x: center.x + (Math.random() * 2 - 1) * spreadX,
          y: minY + Math.random() * (maxY - minY),
        }
        const peers = nextMarkers.filter(marker => marker.zone === zone)
        const clearance = peers.length ? Math.min(...peers.map(marker =>
          Math.max(Math.abs(marker.x - candidate.x) / (cardWidth + 24),
            Math.abs(marker.y - candidate.y) / (cardHeight + 32)))) : Infinity
        if (clearance > bestClearance) {
          position = candidate
          bestClearance = clearance
        }
        if (clearance >= 1) break
      }
      nextMarkers.push({ id, report, zone, scale: 1, ...position,
        vx: (Math.random() - 0.5) * 0.5, vy: (Math.random() - 0.5) * 0.5, dragging: false })
    }
    return nextMarkers
}

export default function Home() {
  const [history, setHistory] = useState<Visit[]>([{ path: "", reports: null }])
  const [pastScans, setPastScans] = useState<SavedScan[]>([])
  const [scanActionNotice, setScanActionNotice] = useState("")
  const [storageNotice, setStorageNotice] = useState("")
  const [cursor, setCursor] = useState(0)
  const [scanPath, setScanPath] = useState("")
  const [folderQueue, setFolderQueue] = useState<string[]>([])
  const [batchFolders, setBatchFolders] = useState<BatchFolder[]>([])
  const [batchProgress, setBatchProgress] = useState({ current: 0, total: 0 })
  const pastScansRef = useRef<SavedScan[]>([])
  const [query, setQuery] = useState("")
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all")
  const [unsignedOnly, setUnsignedOnly] = useState(false)
  const [filtersCollapsed, setFiltersCollapsed] = useState(true)
  const [frozen, setFrozen] = useState(true)
  const frozenRef = useRef(true)
  const filtersRef = useRef({ query: "", risk: "all" as RiskFilter, unsigned: false })
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState("")
  const [markers, setMarkers] = useState<Marker[]>([])
  const [selection, setSelection] = useState<{ id: string; rect: DOMRect } | null>(null)
  const [compact, setCompact] = useState(false)
  const markersRef = useRef<Marker[]>([])
  const dragTargets = useRef(new Map<string, { x: number; y: number }>())
  const sizes = useRef(new Map<string, Size>())
  const boardRef = useRef<HTMLDivElement>(null)
  const bannerRef = useRef<HTMLDivElement>(null)
  const socketRef = useRef<WebSocket | null>(null)
  const scanRevealTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const compactRef = useRef(false)
  const visit = history[cursor]

  const stopScan = useCallback(() => {
    if (scanRevealTimer.current !== null) clearTimeout(scanRevealTimer.current)
    scanRevealTimer.current = null
    const socket = socketRef.current
    socketRef.current = null
    socket?.close()
    setScanning(false)
    setBatchFolders(folders => folders.map(folder =>
      folder.status === "waiting" || folder.status === "scanning" ? { ...folder, status: "stopped" } : folder))
  }, [])

  useEffect(() => () => {
    if (scanRevealTimer.current !== null) clearTimeout(scanRevealTimer.current)
    const socket = socketRef.current
    socketRef.current = null
    socket?.close()
  }, [])

  useEffect(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(SCAN_STORAGE_KEY) ?? "[]")
      if (Array.isArray(saved)) {
        const restored = saved.filter((scan): scan is SavedScan =>
          typeof scan?.id === "string" && typeof scan?.path === "string" &&
          typeof scan?.scannedAt === "string" && scan?.reports &&
          typeof scan.reports === "object" && !Array.isArray(scan.reports) &&
          Object.values(scan.reports).every(report =>
            (report as Report)?.analysis?.file && (report as Report)?.risk_assessment?.risk))
        pastScansRef.current = restored
        // eslint-disable-next-line react-hooks/set-state-in-effect
        setPastScans(restored)
      }
    } catch { /* A blocked or unavailable store does not prevent scanning. */ }
  }, [])

  function saveScan(path: string, reports: ReportMap) {
    const saved = { id: crypto.randomUUID(), scannedAt: new Date().toISOString(), path, reports }
    const next = [saved, ...pastScansRef.current]
    pastScansRef.current = next
    setPastScans(next)
    try {
      localStorage.setItem(SCAN_STORAGE_KEY, JSON.stringify(next))
      setStorageNotice("")
    } catch {
      setStorageNotice("Storage is unavailable or full. New scans are kept for this session only.")
    }
    return saved
  }

  function persistPastScans(next: SavedScan[]) {
    pastScansRef.current = next
    try {
      localStorage.setItem(SCAN_STORAGE_KEY, JSON.stringify(next))
      setStorageNotice("")
    } catch {
      setStorageNotice("Could not update device storage. This change applies to this session only.")
    }
    setPastScans(next)
  }

  function deletePastScan(saved: SavedScan) {
    persistPastScans(pastScans.filter(scan => scan.id !== saved.id))
    setBatchFolders(folders => folders.filter(folder => folder.scan?.id !== saved.id))
    setScanActionNotice(`Deleted ${saved.path}.`)
    const remaining = history.filter(entry => entry.scanId !== saved.id)
    const active = history[cursor]
    setHistory(remaining)
    setCursor(Math.max(0, remaining.indexOf(active)))
  }

  async function copyTranscript(saved: SavedScan) {
    try {
      await navigator.clipboard.writeText(scanTranscript(saved))
      setScanActionNotice(`Copied transcript for ${saved.path}.`)
    } catch {
      setScanActionNotice("Clipboard access was unavailable. Use Download transcript instead.")
    }
  }

  function downloadTranscript(saved: SavedScan) {
    const url = URL.createObjectURL(new Blob([scanTranscript(saved)], { type: "text/plain;charset=utf-8" }))
    const link = document.createElement("a")
    link.href = url
    const name = saved.path.split(/[\\/]/).filter(Boolean).pop() ?? "scan"
    link.download = `Guardia-${name.replace(/[^a-zA-Z0-9._-]/g, "_")}-${saved.scannedAt.replace(/[:.]/g, "-")}.txt`
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
    setScanActionNotice(`Transcript download started for ${saved.path}.`)
  }

  function openPastScan(saved: SavedScan) {
    stopScan()
    setBatchFolders(folders => folders.some(folder => folder.scan?.id === saved.id)
      ? folders : [{ path: saved.path, status: "complete", scan: saved }])
    const previous = history.slice(0, cursor + 1)
    setHistory([...previous, { path: saved.path, reports: saved.reports, scanId: saved.id }])
    setCursor(previous.length)
    showVisit(saved)
  }

  function viewAllFolders() {
    const completed = batchFolders.filter(folder => folder.scan)
    if (!completed.length || scanning) return
    const reports: ReportMap = {}
    for (const folder of completed) {
      for (const [filePath, report] of Object.entries(folder.scan!.reports)) {
        // Keep the source folder in the identity so identical relative names
        // from different scans never overwrite one another.
        reports[`${folder.path} › ${filePath}`] = report
      }
    }
    const next: Visit = { path: `All folders (${completed.length})`, paths: completed.map(folder => folder.path), reports }
    const previous = history.slice(0, cursor + 1)
    setHistory([...previous, next])
    setCursor(previous.length)
    showVisit(next)
  }

  function showVisit(next: Visit) {
    setQuery(""); setRiskFilter("all"); setUnsignedOnly(false)
    filtersRef.current = { query: "", risk: "all", unsigned: false }
    setSelection(null)
    setError("")
    setScanPath(next.path)
    const width = boardRef.current?.getBoundingClientRect().width ?? Math.max(1, window.innerWidth - (filtersCollapsed ? 44 : 260))
    const top = bannerRef.current?.getBoundingClientRect().bottom ?? 120
    dragTargets.current.clear()
    const nextCompact = Object.keys(next.reports ?? {}).length * 250 * 180 / Math.max(1, width * (window.innerHeight - top)) > 0.38
    compactRef.current = nextCompact
    setCompact(nextCompact)
    const nextMarkers = createMarkers(next.reports, width, top, window.innerHeight)
    markersRef.current = nextMarkers
    setMarkers(nextMarkers)
  }

  function navigate(nextCursor: number) {
    stopScan()
    setCursor(nextCursor)
    showVisit(history[nextCursor])
  }

  function restart() {
    stopScan()
    const initial = { path: "", reports: null }
    setHistory([initial])
    setCursor(0)
    setFolderQueue([])
    setBatchFolders([])
    sizes.current.clear()
    showVisit(initial)
  }

  function chooseFolders(paths: string[]) {
    if (!paths.length) return
    if (!scanPath.trim()) {
      setScanPath(paths[0])
      setFolderQueue(current => [...new Set([...current.filter(Boolean), ...paths.slice(1)])])
    } else {
      setFolderQueue(current => [...new Set([...current.filter(Boolean), ...paths.filter(path => path !== scanPath)])])
    }
  }

  function scan(requestedPaths: string[]) {
    const paths = [...new Set(requestedPaths.map(path => path.trim()).filter(Boolean))]
    if (!paths.length || socketRef.current) return
    const invalid = paths.find(path => !path.startsWith("/") && !/^[A-Za-z]:[\\/]/.test(path) && !path.startsWith("\\\\"))
    if (invalid) {
      setError(`Enter a full folder path for “${invalid}”, such as /Users/you/Documents or C:\\Users\\you\\Documents.`)
      return
    }
    setError("")
    setScanning(true)
    setBatchFolders(paths.map(path => ({ path, status: "waiting" })))
    setSelection(null)
    let navigation = history.slice(0, cursor + 1)
    if (!visit.reports) navigation[cursor] = { path: paths[0], reports: null }

    function run(index: number) {
      const path = paths[index]
      setBatchFolders(folders => folders.map(folder => folder.path === path ? { ...folder, status: "scanning" } : folder))
      setScanPath(path)
      setBatchProgress({ current: index + 1, total: paths.length })
      const startedAt = performance.now()
      const socket = new WebSocket("ws://localhost:8000/path")
      socketRef.current = socket
      socket.onopen = () => socket.send(JSON.stringify({ path }))
      socket.onmessage = (event) => {
        if (socketRef.current !== socket) return
        try {
          const reports = JSON.parse(event.data) as ReportMap
          if (!reports || typeof reports !== "object" || Array.isArray(reports) ||
              !Object.values(reports).every(report => report?.analysis?.file && report?.risk_assessment?.risk)) {
            throw new Error("Invalid scan response")
          }
          socket.onmessage = null
          socket.onclose = null
          socket.onerror = null
          socket.close()
          scanRevealTimer.current = setTimeout(() => {
            if (socketRef.current !== socket) return
            const saved = saveScan(path, reports)
            setBatchFolders(folders => folders.map(folder => folder.path === path ? { ...folder, status: "complete", scan: saved } : folder))
            const next = { path, reports, scanId: saved.id }
            navigation = [...navigation, next]
            setHistory(navigation)
            setCursor(navigation.length - 1)
            showVisit(next)
            setFolderQueue(queued => queued.filter(item => item !== path))
            scanRevealTimer.current = null
            if (index + 1 < paths.length) run(index + 1)
            else { stopScan(); void playRetroSound("complete") }
          }, Math.max(0, 1500 - (performance.now() - startedAt)))
        } catch {
          setBatchFolders(folders => folders.map(folder => folder.path === path ? { ...folder, status: "failed" } : folder))
          setError(`Invalid report for ${path}. Queue stopped; completed scans are saved.`)
          stopScan()
        }
      }
      socket.onerror = () => {
        if (socketRef.current !== socket) return
        setBatchFolders(folders => folders.map(folder => folder.path === path ? { ...folder, status: "failed" } : folder))
        setError(`Could not scan ${path}. Queue stopped; completed scans are saved.`)
        stopScan()
      }
      socket.onclose = () => {
        if (socketRef.current !== socket) return
        setBatchFolders(folders => folders.map(folder => folder.path === path ? { ...folder, status: "failed" } : folder))
        setError(`Scan interrupted for ${path}. Queue stopped; completed scans are saved.`)
        stopScan()
      }
    }
    run(0)
  }

  const measure = useCallback((id: string, width: number, height: number) => {
    sizes.current.set(id, { width, height })
  }, [])

  useEffect(() => {
    let frame = 0, previous = 0
    const tick = (now: number) => {
      const dt = previous ? Math.min(2, (now - previous) / (1000 / 60)) : 1
      previous = now
      const board = boardRef.current?.getBoundingClientRect()
      const width = board?.width ?? window.innerWidth, height = board?.bottom ?? window.innerHeight
      const top = board?.top ?? bannerRef.current?.getBoundingClientRect().bottom ?? 0
      if (frozenRef.current) {
        const current = markersRef.current.map(marker => {
          const next = { ...marker }
          const size = sizes.current.get(marker.id) ?? { width: 250, height: 180 }
          keepInside(next, { width: size.width * marker.scale, height: size.height * marker.scale }, { left: 0, top, right: width, bottom: height })
          return next
        })
        markersRef.current = current
        if (current.length) setMarkers(current)
        frame = requestAnimationFrame(tick)
        return
      }
      const filters = filtersRef.current
      const current = markersRef.current.filter(marker => reportMatches(marker.id, marker.report, filters.query, filters.risk, filters.unsigned)).map(marker => ({ ...marker }))
      const density = current.length * 250 * 180 / Math.max(1, width * (height - top))
      const nextCompact = density > (compactRef.current ? 0.24 : 0.38)
      if (nextCompact !== compactRef.current) {
        compactRef.current = nextCompact
        setCompact(nextCompact)
      }
      const bounds = { left: 0, top, right: width, bottom: height }
      const sizeOf = (marker: Marker) => {
        const size = sizes.current.get(marker.id) ?? { width: nextCompact ? 180 : 250, height: nextCompact ? 72 : 180 }
        const center = zoneCenter(marker.zone, width, top, height)
        const scale = zoneScale(marker.x, marker.y, center, width, height - top)
        marker.scale = scale
        return { width: size.width * scale, height: size.height * scale, radius: 2 * scale }
      }
      let travel = 0
      for (const marker of current) {
        const target = dragTargets.current.get(marker.id)
        if (marker.dragging && target) {
          marker.vx = (target.x - marker.x) / dt
          marker.vy = (target.y - marker.y) / dt
        } else if (!marker.dragging) {
          const center = zoneCenter(marker.zone, width, top, height)
          // Only guide cards back when they leave their lane. Inside it,
          // there is no shared attraction point making them stick together.
          const halfWidth = sizeOf(marker).width / 2
          const left = center.x - width / 6 + halfWidth
          const right = center.x + width / 6 - halfWidth
          const targetX = left <= right ? Math.max(left, Math.min(right, marker.x)) : center.x
          marker.vx += (targetX - marker.x) * 0.003 * dt
          marker.vx *= Math.pow(0.97, dt); marker.vy *= Math.pow(0.97, dt)
          if (Math.abs(marker.vx) < 0.015) marker.vx = 0
          if (Math.abs(marker.vy) < 0.015) marker.vy = 0
        }
        travel = Math.max(travel, Math.hypot(marker.vx, marker.vy) * dt)
      }
      // Sweep fast pointer motion in small steps so it cannot skip another card.
      const steps = Math.max(1, Math.ceil(travel / 8))
      for (let step = 0; step < steps; step++) {
        for (const marker of current) {
          marker.x += marker.vx * dt / steps; marker.y += marker.vy * dt / steps
        }
        for (let pass = 0; pass < 5; pass++) {
          for (let i = 0; i < current.length; i++) {
            for (let j = i + 1; j < current.length; j++) {
              separate(current[i], current[j], sizeOf(current[i]), sizeOf(current[j]))
            }
          }
          for (const marker of current) keepInside(marker, sizeOf(marker), bounds)
        }
      }
      const updated = new Map(current.map(marker => [marker.id, marker]))
      markersRef.current = markersRef.current.map(marker => updated.get(marker.id) ?? marker)
      if (current.length) setMarkers(markersRef.current)
      frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [])

  function updateMarker(id: string, changes: Partial<Marker>) {
    markersRef.current = markersRef.current.map(marker => marker.id === id ? { ...marker, ...changes } : marker)
    setMarkers(markersRef.current)
  }

  function renderMarker(marker: Marker) {
    return (
        <ReportMarker key={marker.id} filePath={marker.id} report={marker.report}
          x={marker.x} y={marker.y} compact={compact}
          scale={marker.scale}
          onMeasure={measure}
          onDragStart={() => {
            dragTargets.current.set(marker.id, { x: marker.x, y: marker.y })
            updateMarker(marker.id, { dragging: true, vx: 0, vy: 0 })
          }}
          onDragMove={(x, y) => {
            if (frozen) updateMarker(marker.id, { x, y, vx: 0, vy: 0 })
            else dragTargets.current.set(marker.id, { x, y })
          }}
          onDragEnd={(vx, vy) => {
            dragTargets.current.delete(marker.id)
            updateMarker(marker.id, { dragging: false, vx: frozen ? 0 : vx, vy: frozen ? 0 : vy })
          }}
          onOpen={rect => setSelection({ id: marker.id, rect })}
        />
    )
  }
  const visibleMarkers = markers.filter(marker => reportMatches(marker.id, marker.report, query, riskFilter, unsignedOnly))
  const counts = { safe: 0, review: 0, unsafe: 0 }
  for (const marker of markers) counts[marker.zone]++
  const highest = markers.reduce<Marker | null>((best, marker) => !best || marker.report.risk_assessment.risk.percentage > best.report.risk_assessment.risk.percentage ? marker : best, null)

  const selected = markers.find(marker => marker.id === selection?.id)
  return (
    <div className="retro-desktop relative flex h-screen min-h-screen w-screen flex-col items-center overflow-hidden" onClickCapture={event => {
      if ((event.target as HTMLElement).closest("button:not(:disabled), summary")) void playRetroSound("click")
    }}>
      <div ref={bannerRef} className="relative z-40 w-full">
        <Banner>
          <nav aria-label="Scan navigation" className="flex flex-wrap justify-end gap-2">
            <button className="retro-button inline-flex items-center gap-2 px-4" onClick={() => navigate(0)} aria-current={cursor === 0 ? "page" : undefined}><RetroIcon name="home" />Home</button>
            <button className="retro-button px-4" disabled={cursor === 0} onClick={() => navigate(cursor - 1)}>← Back</button>
            <button className="retro-button px-4" disabled={cursor === history.length - 1} onClick={() => navigate(cursor + 1)}>Forward →</button>
            <button className="retro-button px-4" disabled={!visit.reports || scanning} onClick={() => scan(visit.paths ?? [scanPath])}>{scanning ? "Scanning…" : "↻ Rescan"}</button>
            <button className="retro-button px-4" onClick={restart}>Restart</button>
            <Settings />
          </nav>
          {visit.reports !== null && batchFolders.length > 0 ? (
            <div className="mt-2 flex flex-wrap items-center justify-end gap-2 text-xs text-[#ffe1bf]">
              <label htmlFor="batch-folder-view" className="sr-only">View scanned folders</label>
              <select
                id="batch-folder-view"
                className="retro-input-frame min-h-8 max-w-[min(380px,85vw)] min-w-0 truncate px-2 text-[#70535f]"
                value={visit.paths ? "all" : batchFolders.some(folder => folder.scan?.id === visit.scanId) ? visit.scanId ?? "" : ""}
                disabled={scanning}
                onChange={event => {
                  if (event.target.value === "all") viewAllFolders()
                  else {
                    const folder = batchFolders.find(folder => folder.scan?.id === event.target.value)
                    if (folder?.scan) openPastScan(folder.scan)
                  }
                }}
              >
                <option value="" disabled>Select a folder…</option>
                <option value="all" disabled={!batchFolders.some(folder => folder.scan)}>View all together</option>
                {batchFolders.map(folder => (
                  <option key={folder.path} value={folder.scan?.id ?? `pending:${folder.path}`} disabled={!folder.scan}>
                    {folder.path} — {folder.scan ? `${Object.keys(folder.scan.reports).length} reports` : folder.status === "scanning" ? "Scanning…" : folder.status === "waiting" ? "Waiting" : folder.status === "failed" ? "Failed" : "Not scanned"}
                  </option>
                ))}
              </select>
              <span role="status">{batchFolders.filter(folder => folder.status === "complete").length}/{batchFolders.length} scanned</span>
            </div>
          ) : <p className="mt-2 text-right text-xs text-[#ffe1bf]">Choose a folder to get started</p>}
          {error && <p role="alert" className="mt-2 max-w-md bg-[#fff9e6] p-2 text-xs text-[#b32635]">{error}</p>}
        </Banner>

      </div>
      {visit.reports === null && (
        <div className="home-workspace">
          <aside className="retro-panel past-scans-sidebar" aria-label="Past scans">
            <h2 className="retro-heading flex items-center gap-2"><RetroIcon name="sections" size={20} />Past scans</h2>
            <p className="my-3 text-xs text-[#805775]">Saved on this device. Open a scan to revisit its reports.</p>
            {storageNotice && <p role="status" className="mb-3 text-xs text-[#956014]">{storageNotice}</p>}
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <p role="status" aria-live="polite" className="text-xs">{scanActionNotice}</p>
            </div>
            {!pastScans.length ? <p className="py-3 text-sm">No scans yet. Your completed scans will appear here.</p> : (
              <ul className="flex flex-col gap-2">
                {pastScans.map(saved => (
                  <li key={saved.id} className="flex flex-wrap items-center gap-2 border-2 border-[#cbaa9c] bg-[#fffdf5] p-2">
                    <RetroIcon name="file" size={24} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-bold" title={saved.path}>{saved.path}</p>
                      <p className="mt-1 truncate text-xs text-[#805775]"><time dateTime={saved.scannedAt}>{new Date(saved.scannedAt).toLocaleString()}</time> · {Object.keys(saved.reports).length} files</p>
                    </div>
                    <button className="retro-button px-3" aria-label={`Open scan of ${saved.path} from ${new Date(saved.scannedAt).toLocaleString()}`} onClick={() => openPastScan(saved)}>Open</button>
                    <div className="flex shrink-0 gap-1" role="group" aria-label={`Actions for scan of ${saved.path}`}>
                      <button className="retro-button flex w-9 items-center justify-center" title="Copy transcript" aria-label={`Copy transcript for ${saved.path}`} onClick={() => copyTranscript(saved)}><RetroIcon name="copy" /></button>
                      <button className="retro-button flex w-9 items-center justify-center" title="Download transcript" aria-label={`Download transcript for ${saved.path}`} onClick={() => downloadTranscript(saved)}><RetroIcon name="download" /></button>
                      <button className="retro-button flex w-9 items-center justify-center" title="Delete scan" aria-label={`Delete scan of ${saved.path}`} onClick={() => deletePastScan(saved)}><RetroIcon name="trash" /></button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </aside>
          <main className="home-scan-panel">
            <Form>
              <div className="col-span-full space-y-4">
                <p className="text-xs text-[#805775]">Enter the full path to each folder on the scanner’s computer. Use Browse in the desktop app to select folders.</p>
                <FolderPicker path={scanPath} onPathChange={setScanPath} onFoldersSelected={chooseFolders} disabled={scanning} />
                {folderQueue.map((path, index) => (
                  <div key={index} className="flex items-end gap-2">
                    <FolderPicker path={path} onPathChange={value => setFolderQueue(paths => paths.map((item, i) => i === index ? value : item))} disabled={scanning} />
                    <button className="retro-button flex h-11 w-10 shrink-0 items-center justify-center" disabled={scanning} title="Remove folder" aria-label={`Remove folder ${index + 2}`} onClick={() => setFolderQueue(paths => paths.filter((_, i) => i !== index))}><RetroIcon name="trash" /></button>
                  </div>
                ))}
                <button className="retro-button px-4" disabled={scanning} onClick={() => setFolderQueue(paths => [...paths, ""])}>+ Add another folder</button>
                <button className="retro-button block w-full px-6" disabled={![scanPath, ...folderQueue].some(path => path.trim()) || scanning} onClick={() => scan([scanPath, ...folderQueue])}>{scanning ? "Scanning…" : `Scan All (${new Set([scanPath, ...folderQueue].map(path => path.trim()).filter(Boolean)).size})`}</button>
                <p className="text-xs text-[#805775]">Scans run from top to bottom, one folder at a time.</p>
              </div>
            </Form>
          </main>
        </div>
      )}
      {scanning && (
        <div className="pointer-events-none fixed inset-0 z-[80] flex items-center justify-center bg-[#4a2b45]/20">
          <div className="retro-panel w-[min(360px,90vw)]" role="status" aria-live="polite">
            <div className="mb-3 flex items-center gap-3 font-bold"><span className="retro-loading-circle" aria-hidden="true">{Array.from({ length: 8 }, (_, index) => (
              <span key={index} style={{ transform: `rotate(${index * 45}deg) translateY(-12px) rotate(${-index * 45}deg)`, animationDelay: `${index * 0.1 - 0.8}s` }} />
            ))}</span>Scanning {batchProgress.current} of {batchProgress.total}…</div>
            <p className="mb-3 truncate text-xs">{scanPath}</p>
            <div className="retro-loading-track" aria-hidden="true"><div className="retro-loading-blocks" /></div>
            <p className="mt-3 text-xs">Inspecting files. Please wait.</p>
          </div>
        </div>
      )}
      {visit.reports && (
        <div className="results-workspace">
        <div ref={boardRef} className="report-board" aria-label="Reports grouped by scan result">
          {(["safe", "review", "unsafe"] as Zone[]).map(zone => (
            <section key={zone} className={`report-zone report-zone-${zone}`} aria-label={`${zone} reports`}>
              <h2 title={zone === "review" ? "Needs review" : zone === "safe" ? "Safe" : "Unsafe"}>
                <RetroIcon name={zone === "safe" ? "happy" : zone === "unsafe" ? "unhappy" : "neutral"} size={32} />
                <span className="sr-only">{zone === "review" ? "Needs review" : zone === "safe" ? "Safe" : "Unsafe"}</span>
                <span>{visibleMarkers.filter(marker => marker.zone === zone).length} files</span>
              </h2>
            </section>
          ))}
        </div>
          <aside className={`retro-panel filters-sidebar ${filtersCollapsed ? "is-collapsed" : ""}`} aria-label="Scan summary and filters">
            <button
              className="retro-window-control sidebar-toggle mb-3 flex w-full items-center justify-center gap-2 px-1"
              aria-expanded={!filtersCollapsed}
              aria-controls="filters-sidebar-content"
              aria-label={filtersCollapsed ? "Expand filters sidebar" : "Collapse filters sidebar"}
              title={filtersCollapsed ? "Expand filters" : "Collapse filters"}
              onClick={() => setFiltersCollapsed(value => !value)}
            ><RetroIcon name={filtersCollapsed ? "chevron-left" : "chevron-right"} size={16} />{!filtersCollapsed && "Collapse"}</button>
            {filtersCollapsed && <span className="filters-rail-label">Filters{query || riskFilter !== "all" || unsignedOnly ? " • Active" : ""}</span>}
            <div id="filters-sidebar-content" hidden={filtersCollapsed}>
            <h2 className="retro-window-title mb-4"><span className="inline-flex items-center gap-2"><RetroIcon name="controls" />File filters</span></h2>
            <fieldset className="retro-settings-group flex flex-col gap-2 text-xs" aria-label="Scan summary"><legend>Scan summary</legend>
              <strong>{markers.length} files</strong><span className="text-[#287044]">Safe: {counts.safe}</span><span className="text-[#956014]">Review: {counts.review}</span><span className="text-[#b32635]">Unsafe: {counts.unsafe}</span>
              {highest && <span className="max-w-full truncate" title={highest.id}>Highest risk: {highest.report.analysis.file.file_name} ({highest.report.risk_assessment.risk.percentage}%)</span>}
            </fieldset>
            <fieldset className="retro-settings-group mt-4 flex flex-col gap-3"><legend>Find files</legend>
              <label htmlFor="file-search" className="text-xs">File name or path</label>
              <input id="file-search" aria-label="Search files" placeholder="Search files or paths…" value={query} onChange={event => { setQuery(event.target.value); filtersRef.current.query = event.target.value }} className="retro-input-frame min-w-0 w-full px-3 py-2 text-sm" />
              <label htmlFor="risk-filter" className="text-xs">Risk level</label>
              <select id="risk-filter" aria-label="Filter by risk" value={riskFilter} onChange={event => { setRiskFilter(event.target.value as RiskFilter); filtersRef.current.risk = event.target.value as RiskFilter }} className="retro-input-frame px-2 py-2 text-sm"><option value="all">All risk levels</option><option value="safe">Safe</option><option value="review">Needs review</option><option value="unsafe">Unsafe</option></select>
              <label className="flex items-center gap-1 text-xs"><input className="retro-checkbox" type="checkbox" checked={unsignedOnly} onChange={event => { setUnsignedOnly(event.target.checked); filtersRef.current.unsigned = event.target.checked }} />Unsigned only</label>
              <button className="retro-window-control min-h-9 px-3 text-xs" aria-pressed={frozen} onClick={() => { frozenRef.current = !frozen; setFrozen(!frozen); markersRef.current = markersRef.current.map(marker => ({ ...marker, vx: 0, vy: 0 })) }}>{frozen ? "Unfreeze" : "Freeze"}</button>
              <span className="retro-settings-status text-xs" role="status">Showing {visibleMarkers.length} of {markers.length}</span>
            </fieldset>
            </div>
          </aside>
        </div>
      )}
      {visit.reports && markers.length > 0 && !visibleMarkers.length && <p className="pointer-events-none absolute bottom-8 z-20 bg-[#fff9e6] p-3 text-sm">No files match these filters.</p>}
      {visit.reports && !markers.length && <p className="retro-panel mt-8">No files were reported. Go back to choose another folder.</p>}
      {visibleMarkers.map(renderMarker)}
      {selected && selection && <ReportDetailModal filePath={selected.id} report={selected.report} originRect={selection.rect} onClose={() => setSelection(null)} />}
    </div>
  )
}
