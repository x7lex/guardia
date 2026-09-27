"use client"

import React, { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from "react"
import RetroIcon, { RetroIconName } from "@/components/retro-icon"
import { toCanvas } from "html-to-image"
import { Report, riskAppearance } from "@/components/report-marker"

interface ReportDetailModalProps {
    filePath: string
    report: Report
    originRect: DOMRect | null
    onClose: () => void
}

function smoothstep(value: number) {
    const t = Math.max(0, Math.min(1, value))
    return t * t * t * (t * (t * 6 - 15) + 10)
}

function drawGenie(
    ctx: CanvasRenderingContext2D,
    snapshot: HTMLCanvasElement,
    rect: DOMRect,
    target: DOMRect,
    progress: number,
) {
    ctx.clearRect(0, 0, window.innerWidth, window.innerHeight)
    const travel = smoothstep(progress)
    const top = target.top + (rect.top - target.top) * travel
    const height = target.height + (rect.height - target.height) * travel
    const below = target.top + target.height / 2 > rect.top + rect.height / 2
    const rows = Math.ceil(rect.height)
    const sourceRow = snapshot.height / rows
    ctx.globalAlpha = Math.min(1, progress / 0.12)
    for (let row = 0; row < rows; row++) {
        const v = row / rows
        // The edge nearest the marker stays narrow longer, forming the
        // curved neck of the genie. Closing retraces the same geometry.
        const distance = below ? 1 - v : v
        const delay = (1 - distance) * 0.32
        const spread = smoothstep((progress - delay) / (1 - delay))
        const left = target.left + (rect.left - target.left) * spread
        const width = target.width + (rect.width - target.width) * spread
        ctx.drawImage(snapshot, 0, row * sourceRow, snapshot.width, sourceRow,
            left, top + v * height, width, height / rows + 0.5)
    }
    ctx.globalAlpha = 1
}

export default function ReportDetailModal({
    filePath,
    report,
    originRect,
    onClose,
}: ReportDetailModalProps) {
    const modalRef = useRef<HTMLDivElement>(null)
    const backdropRef = useRef<HTMLDivElement>(null)
    const canvasRef = useRef<HTMLCanvasElement>(null)
    const animationRef = useRef(0)
    const snapshotRef = useRef<HTMLCanvasElement | null>(null)
    const rectRef = useRef<DOMRect | null>(null)
    const progressRef = useRef(0)
    const closingRef = useRef(false)
    const mountedRef = useRef(false)
    const [showAdvanced, setShowAdvanced] = useState(false)
    const advancedId = useId()
    const [maximized, setMaximized] = useState(false)
    const resizeAnimationRef = useRef<Animation | null>(null)
    const resizeFromRef = useRef<DOMRect | null>(null)

    function toggleMaximized() {
        if (closingRef.current || !modalRef.current) return
        // Read the current frame before cancelling, so rapid toggles stay smooth.
        resizeFromRef.current = modalRef.current.getBoundingClientRect()
        resizeAnimationRef.current?.cancel()
        setMaximized(value => !value)
    }

    useLayoutEffect(() => {
        const modal = modalRef.current
        const from = resizeFromRef.current
        resizeFromRef.current = null
        if (!modal || !from || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return
        const to = modal.getBoundingClientRect()
        const maxHeight = `${Math.max(from.height, to.height)}px`
        const animation = modal.animate([
            { width: `${from.width}px`, height: `${from.height}px`, maxHeight },
            { width: `${to.width}px`, height: `${to.height}px`, maxHeight },
        ], {
            duration: 360,
            easing: "cubic-bezier(0.22, 1, 0.36, 1)",
        })
        resizeAnimationRef.current = animation
        return () => animation.cancel()
    }, [maximized])
    const { file, imports, signature, suspicious_instructions } = report.analysis
    const { risk, reasons } = report.risk_assessment
    const appearance = riskAppearance(risk.verdict ?? risk.level)
    const levelColor = appearance.color

    const capture = useCallback(async () => {
        const modal = modalRef.current
        if (!modal) return
        const rect = modal.getBoundingClientRect()
        // Opacity is not inherited: descendants remain visible in the clone.
        // Using visibility here would bake hidden styles into every child.
        const snapshot = await toCanvas(modal, {
            pixelRatio: Math.min(window.devicePixelRatio || 1, 2),
            style: { opacity: "1" },
        })
        // Mask the source itself: rounding a warped shape's bounding box
        // leaves square corners where the curved sides meet its top and bottom.
        const ctx = snapshot.getContext("2d")
        if (ctx) {
            const ratio = snapshot.width / rect.width
            ctx.globalCompositeOperation = "destination-in"
            ctx.beginPath()
            ctx.roundRect(0, 0, snapshot.width, snapshot.height, 2 * ratio)
            ctx.fill()
            ctx.globalCompositeOperation = "source-over"
        }
        if (!mountedRef.current) return
        snapshotRef.current = snapshot
        rectRef.current = rect
    }, [])

    const animate = useCallback((opening: boolean, done: () => void) => {
        const modal = modalRef.current
        const canvas = canvasRef.current
        const snapshot = snapshotRef.current
        const rect = rectRef.current
        const ctx = canvas?.getContext("2d")
        if (!modal || !canvas || !snapshot || !rect || !ctx ||
            window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
            if (modal) modal.style.opacity = "1"
            if (backdropRef.current) backdropRef.current.style.opacity = "1"
            progressRef.current = opening ? 1 : 0
            done()
            return
        }
        cancelAnimationFrame(animationRef.current)
        const dpr = Math.min(window.devicePixelRatio || 1, 2)
        canvas.width = Math.round(window.innerWidth * dpr)
        canvas.height = Math.round(window.innerHeight * dpr)
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
        ctx.imageSmoothingEnabled = true
        ctx.imageSmoothingQuality = "high"
        const target = originRect ?? new DOMRect(window.innerWidth / 2 - 60, window.innerHeight - 40, 120, 24)
        const from = progressRef.current
        const to = opening ? 1 : 0
        const duration = Math.max(80, 580 * Math.abs(to - from))
        const started = performance.now()
        modal.style.opacity = "0"
        canvas.style.visibility = "visible"

        const frame = (now: number) => {
            const time = Math.min(1, (now - started) / duration)
            const progress = from + (to - from) * time
            progressRef.current = progress
            drawGenie(ctx, snapshot, rect, target, progress)
            if (backdropRef.current) backdropRef.current.style.opacity = String(smoothstep(progress))
            if (time < 1) {
                animationRef.current = requestAnimationFrame(frame)
            } else {
                if (opening) modal.style.opacity = "1"
                canvas.style.visibility = "hidden"
                done()
            }
        }
        // Paint before hiding the live content can reach the screen.
        frame(started)
    }, [originRect])

    useLayoutEffect(() => {
        mountedRef.current = true
        const modal = modalRef.current
        if (modal) modal.style.opacity = "0"
        if (backdropRef.current) backdropRef.current.style.opacity = "0"
        capture().then(() => {
            if (mountedRef.current && !closingRef.current) animate(true, () => {})
        }).catch(() => {
            if (!mountedRef.current || closingRef.current) return
            if (modal) modal.style.opacity = "1"
            if (backdropRef.current) backdropRef.current.style.opacity = "1"
            progressRef.current = 1
        })
        return () => {
            mountedRef.current = false
            cancelAnimationFrame(animationRef.current)
        }
    }, [capture, animate])

    const handleClose = useCallback(async () => {
        if (closingRef.current) return
        closingRef.current = true
        // Finish the resize before capturing the closing genie frame.
        try { await resizeAnimationRef.current?.finished } catch { /* A newer resize replaced it. */ }
        if (!mountedRef.current) return
        // Refresh expanded or scrolled content before the closing warp.
        if (progressRef.current === 1) {
            try { await capture() } catch { /* Keep the previous snapshot. */ }
        }
        if (mountedRef.current) animate(false, onClose)
    }, [animate, capture, onClose])

    useEffect(() => {
        function keyDown(event: KeyboardEvent) {
            if (event.key === "Escape") handleClose()
        }
        window.addEventListener("keydown", keyDown)
        return () => window.removeEventListener("keydown", keyDown)
    }, [handleClose])

    const modal = (
        <div
            ref={modalRef}
            role="dialog"
            aria-modal="true"
            aria-label={`Report for ${file.file_name}`}
            className="
                retro-report
                flex
                max-h-[86vh]
                w-[min(640px,92vw)]
                flex-col
                overflow-hidden
                rounded-[2px]
                border-2
                border-[#9c4f8f]
                bg-[#fff9e6]
                shadow-[4px_4px_0px_rgba(156,79,143,0.35)]
            "
            style={{
                clipPath: "inset(0 round 2px)",
                width: maximized ? "100vw" : undefined,
                height: maximized ? "100dvh" : undefined,
                maxHeight: maximized ? "100dvh" : undefined,
                borderColor: levelColor,
                borderStyle: "ridge",
                fontFamily:
                    "'Trebuchet MS', 'Verdana', sans-serif",
            }}
        >
            {/* HEADER */}

            <div
                style={{ background: appearance.header, borderColor: levelColor }}
                className="
                    shrink-0
                    z-10
                    flex
                    items-center
                    justify-between
                    gap-3
                    border-b-2
                    border-[#9c4f8f]
                    bg-gradient-to-r
                    from-[#f6d9ea]
                    to-[#f0cee6]
                    px-5
                    py-3.5
                "
            >
                <div className="flex min-w-0 items-center gap-3">
                    <div
                        className="
                            flex
                            h-9
                            w-9
                            items-center
                            justify-center
                            rounded-[2px]
                            border-2
                            border-[#9c4f8f]
                            bg-white
                            text-lg
                        "
                    >
                        <RetroIcon name="file" size={22} />
                    </div>

                    <div className="min-w-0">
                        <div
                            className="
                                truncate
                                text-[17px]
                                font-bold
                                text-[#6b2d63]
                            "
                        >
                            {
                                file.file_name
                            }
                        </div>

                        <div
                            className="
                                truncate
                                text-xs
                                text-[#8a5f83]
                            "
                        >
                            {
                                filePath
                            }
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-2">
                    <button
                        type="button"
                        aria-label={maximized ? "Restore window" : "Maximize window"}
                        title={maximized ? "Restore window" : "Maximize window"}
                        aria-pressed={maximized}
                        onClick={(event) => {
                            event.stopPropagation()
                            toggleMaximized()
                        }}
                        className="flex h-8 w-8 items-center justify-center border-2 border-[#9c4f8f] bg-white text-[#9c4f8f]"
                    >
                        <RetroIcon name={maximized ? "restore" : "maximize"} size={14} />
                    </button>
                    <button
                        aria-label="Close report"
                        onClick={
                            handleClose
                        }
                        className="
                            flex
                            h-8
                            w-8
                            items-center
                            justify-center
                            rounded-[2px]
                            border-2
                            border-[#9c4f8f]
                            bg-white
                            font-bold
                            text-[#9c4f8f]
                        "
                    >
                        <RetroIcon name="close" size={14} />
                    </button>
                </div>
            </div>

            {/* BODY */}

            <div className="report-scroll-body min-h-0 flex-auto overflow-y-auto">
            <div className="flex flex-col gap-5 p-5">
                <Section title="Overview">
                    <div className="mb-3 flex items-center gap-3">
                        <div
                            className="
                                h-3
                                flex-1
                                overflow-hidden
                                rounded-[2px]
                                border
                                border-[#c98cc0]
                                bg-[#f0d6ea]
                            "
                        >
                            <div
                                style={{
                                    width:
                                        `${risk.points * 10}%`,

                                    background: "#9c7b8d",

                                    height:
                                        "100%",
                                }}
                            />
                        </div>

                        <span
                            className="
                                text-[13px]
                                font-bold
                                text-[#6b2d63]
                            "
                        >
                            {
                                risk.points
                            }
                            /10 triage score
                        </span>
                    </div>

                    <div className="text-sm text-[#4a2b45]">
                        {plainLanguageSummary(
                            risk.verdict ?? risk.level,
                            signature.signed
                        )}
                    </div>

                    <p className="text-xs text-[#805775]">{risk.verdict ?? risk.level}. Static indicators are not a probability of malware or proof of safety.</p>
                    {report.risk_assessment.diagnostics?.limitations?.length ? <ul className="list-disc pl-4 text-xs text-[#805775]">{report.risk_assessment.diagnostics.limitations.map((limitation, index) => <li key={index}>{limitation}</li>)}</ul> : null}
                    {reasons.length >
                        0 && (
                            <ul className="mt-3 flex flex-col gap-1.5">
                                {reasons.map(
                                    (
                                        reason,
                                        i
                                    ) => (
                                        <li
                                            key={
                                                i
                                            }
                                            className="
                                            text-[13px]
                                            text-[#4a2b45]
                                        "
                                        >
                                            •{" "}
                                            {
                                                reason.reason
                                            }
                                        </li>
                                    )
                                )}
                            </ul>
                        )}
                </Section>

                {report.risk_assessment.visibility && (
                    <Section title="Evidence and visibility">
                        <dl className="grid grid-cols-2 gap-x-3 gap-y-2 text-sm">
                            <dt>Verdict</dt><dd className="font-bold">{risk.verdict ?? risk.level}</dd>
                            <dt>Threat evidence</dt><dd>{risk.threat_points ?? risk.points}/10</dd>
                            <dt>Visibility review floor</dt><dd>{risk.uncertainty_floor ?? 0}/10</dd>
                            <dt>Visibility</dt><dd>{report.risk_assessment.visibility.level.replaceAll("_", " ")}</dd>
                            <dt>Visibility index</dt><dd>{report.risk_assessment.visibility.score.toFixed(2)} / 1</dd>
                            <dt>Likely role</dt><dd>{report.risk_assessment.context?.likely_role.replaceAll("_", " ") ?? "Unknown"}</dd>
                        </dl>
                        <p className="mt-3 text-xs text-[#805775]">Triage uses the higher of threat evidence and the bounded visibility floor. The visibility index is a heuristic, not a probability or a measured percentage of code analyzed.</p>
                        <ul className="mt-3 list-disc space-y-1 pl-4 text-xs">{report.risk_assessment.visibility.reasons.map((reason, index) => <li key={index}>{reason.reason}</li>)}</ul>
                    </Section>
                )}
                {report.risk_assessment.trust && (
                    <Section title="Signature and publisher context">
                        <dl className="grid grid-cols-2 gap-x-3 gap-y-2 break-words text-sm">
                            <dt>Signature integrity</dt><dd>{report.risk_assessment.trust.signature_integrity}</dd>
                            <dt>Publisher in certificate</dt><dd>{report.risk_assessment.trust.publisher ?? "None"}</dd>
                            <dt>Publisher verified</dt><dd>{report.risk_assessment.trust.publisher_verified ? "Yes" : "No"}</dd>
                            <dt>Certificate chain</dt><dd>{report.risk_assessment.trust.chain_trust.replaceAll("_", " ")}</dd>
                            <dt>Revocation</dt><dd>{report.risk_assessment.trust.revocation.replaceAll("_", " ")}</dd>
                        </dl>
                    </Section>
                )}
                {!report.risk_assessment.visibility && <p className="text-xs text-[#805775]">Saved with an older scoring model. Rescan the file to see separate threat evidence, visibility and trust.</p>}

                <button
                    type="button"
                    aria-expanded={showAdvanced}
                    aria-controls={advancedId}
                    onClick={(event) => {
                        event.stopPropagation()
                        setShowAdvanced((value) => !value)
                    }}
                    className="
                        self-start
                        rounded-[2px]
                        border-2
                        border-[#9c4f8f]
                        bg-white
                        px-4
                        py-1.5
                        text-[13px]
                        font-bold
                        text-[#9c4f8f]
                    "
                >
                    <span aria-hidden="true" className={`advanced-arrow ${showAdvanced ? "is-open" : ""}`}>▶</span>
                    {showAdvanced ? "Hide advanced details" : "Show advanced details"}
                </button>

                <div
                    id={advancedId}
                    className={`advanced-disclosure ${showAdvanced ? "is-open" : ""}`}
                    aria-hidden={!showAdvanced}
                    inert={!showAdvanced}
                >
                    <div className="advanced-clip">
                    <div className="flex flex-col gap-4">
                        <Card title="Risk breakdown">
                            {reasons.length ===
                                0 ? (
                                <div>
                                    No risk factors
                                    detected.
                                </div>
                            ) : (
                                reasons.map(
                                    (
                                        reason,
                                        i
                                    ) => (
                                        <div
                                            key={
                                                i
                                            }
                                            className="text-[13px] text-[#4a2b45]"
                                        >
                                            {
                                                reason.reason
                                            }{" "}
                                            <b>
                                                (+
                                                {
                                                    reason.points
                                                }
                                                )
                                            </b>
                                        </div>
                                    )
                                )
                            )}
                        </Card>

                        <Card title="File info">
                            <InfoGrid
                                rows={[
                                    [
                                        "Format",
                                        file.format,
                                    ],
                                    [
                                        "Machine",
                                        file.machine,
                                    ],
                                    [
                                        "Entry point",
                                        file.entry_point,
                                    ],
                                    [
                                        "Sections",
                                        String(
                                            file.section_count
                                        ),
                                    ],
                                    [
                                        "SHA-256",
                                        file.sha256,
                                    ],
                                ]}
                            />
                        </Card>

                        <Card title="Sections">
                            <div className="overflow-x-auto">
                                <table className="w-full text-xs">
                                    <thead>
                                        <tr>
                                            <th className="px-2 py-1 text-left">
                                                Name
                                            </th>

                                            <th className="px-2 py-1 text-left">
                                                Entropy
                                            </th>

                                            <th className="px-2 py-1 text-left">
                                                Executable
                                            </th>
                                        </tr>
                                    </thead>

                                    <tbody>
                                        {file.sections.map(
                                            (
                                                section,
                                                i
                                            ) => (
                                                <tr
                                                    key={
                                                        i
                                                    }
                                                >
                                                    <td className="px-2 py-1 font-mono">
                                                        {
                                                            section.name
                                                        }
                                                    </td>

                                                    <td className="px-2 py-1">
                                                        {section.entropy.toFixed(
                                                            2
                                                        )}
                                                    </td>

                                                    <td className="px-2 py-1">
                                                        {section.executable
                                                            ? "Yes"
                                                            : "No"}
                                                    </td>
                                                </tr>
                                            )
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </Card>

                        <Card title="Signature">
                            <InfoGrid
                                rows={[
                                    [
                                        "Signed",
                                        signature.signed
                                            ? "Yes"
                                            : "No",
                                    ],
                                    [
                                        "Integrity",
                                        signature.integrity,
                                    ],
                                    [
                                        "Known CA",
                                        signature.known_ca
                                            ? "Yes"
                                            : "No",
                                    ],
                                ]}
                            />
                        </Card>

                        <Card title="Suspicious instructions">
                            <div className="text-[13px] text-[#4a2b45]">
                                Count:{" "}
                                {
                                    suspicious_instructions.count
                                }
                            </div>

                            <div className="mt-2 flex flex-wrap gap-2">
                                {suspicious_instructions.instructions.map(
                                    (
                                        instruction,
                                        i
                                    ) => (
                                        <span
                                            key={
                                                i
                                            }
                                            className="
                                                rounded
                                                bg-[#f6d9ea]
                                                px-2
                                                py-1
                                                font-mono
                                                text-xs
                                                text-[#6b2d63]
                                            "
                                        >
                                            {
                                                instruction
                                            }
                                        </span>
                                    )
                                )}
                            </div>
                        </Card>

                        <Card
                            title={`Imports (${imports.library_count} libraries, ${imports.function_count} functions)`}
                        >
                            {imports.libraries.map(
                                (
                                    library,
                                    i
                                ) => (
                                    <div
                                        key={
                                            i
                                        }
                                        className="mb-3"
                                    >
                                        <b className="text-[#6b2d63]">
                                            {
                                                library.name
                                            }
                                        </b>

                                        <div className="mt-1 flex flex-wrap gap-1">
                                            {library.functions.map(
                                                (
                                                    fn,
                                                    j
                                                ) => (
                                                    <span
                                                        key={
                                                            j
                                                        }
                                                        className="
                                                            rounded
                                                            border
                                                            border-[#e0b9d8]
                                                            bg-white
                                                            px-1.5
                                                            py-0.5
                                                            font-mono
                                                            text-[11px]
                                                        "
                                                    >
                                                        {
                                                            fn
                                                        }
                                                    </span>
                                                )
                                            )}
                                        </div>
                                    </div>
                                )
                            )}
                        </Card>
                    </div>
                    </div>
                </div>
            </div>
            </div>
        </div>
    )

    return (
        <div
            className={`fixed inset-0 z-[100] flex items-center justify-center ${maximized ? "" : "p-4"}`}
            onClick={handleClose}
        >
            <div
                ref={backdropRef}
                className="absolute inset-0 bg-[#4a2b45]/45 backdrop-blur-[3px]"
                aria-hidden="true"
            />
            <div className="relative" onClick={event => event.stopPropagation()}>{modal}</div>
            <canvas
                ref={canvasRef}
                aria-hidden="true"
                className="pointer-events-none fixed inset-0 h-full w-full"
            />
        </div>
    )
}

function plainLanguageSummary(
    level: string,
    signed: boolean
) {
    const appearance = riskAppearance(level)
    if (appearance.label === "HIGH RISK") {
        return signed ? "Strong risk indicators were found despite an embedded signature." : "Strong risk indicators were found in this unsigned file."
    }
    if (appearance.label === "FEW INDICATORS") return "Few static indicators were found. Review the analysis coverage before trusting this file."
    return "This file needs closer review. Check the findings and coverage limitations."

}

function Section({
    title,
    children,
}: {
    title: string
    children:
    React.ReactNode
}) {
    return (
        <div>
            <div
                className="
                    mb-2
                    border-b
                    border-dashed
                    border-[#c98cc0]
                    pb-1
                    text-[13px]
                    font-bold
                    text-[#9c4f8f]
                "
            >
                <span className="inline-flex items-center gap-2"><RetroIcon name={sectionIcon(title)} />{title}</span>
            </div>

            {children}
        </div>
    )
}

function Card({
    title,
    children,
}: {
    title: string
    children:
    React.ReactNode
}) {
    return (
        <div
            className="
                rounded-sm
                border
                border-[#e0b9d8]
                bg-[#fffdf4]
                p-3.5
            "
        >
            <div
                className="
                    mb-2.5
                    text-[13px]
                    font-bold
                    text-[#9c4f8f]
                "
            >
                <span className="inline-flex items-center gap-2"><RetroIcon name={sectionIcon(title)} />{title}</span>
            </div>

            {children}
        </div>
    )
}

function InfoGrid({
    rows,
}: {
    rows:
    [string, string][]
}) {
    return (
        <div
            className="
                grid
                grid-cols-[auto_1fr]
                gap-x-3.5
                gap-y-1.5
                text-[13px]
            "
        >
            {rows.map(
                ([
                    label,
                    value,
                ]) => (
                    <React.Fragment
                        key={
                            label
                        }
                    >
                        <div className="font-bold text-[#9c4f8f]">
                            {
                                label
                            }
                        </div>

                        <div
                            className={`
                                break-all
                                text-[#4a2b45]

                                ${label ===
                                    "SHA-256"
                                    ? "font-mono"
                                    : ""
                                }
                            `}
                        >
                            {
                                value
                            }
                        </div>
                    </React.Fragment>
                )
            )}
        </div>
    )
}
function sectionIcon(title: string): RetroIconName {
    if (title === "Overview") return "overview"
    if (title === "Risk breakdown") return "risk"
    if (title === "Sections") return "sections"
    if (title === "Signature") return "signature"
    if (title === "Suspicious instructions") return "warning"
    if (title.startsWith("Imports")) return "imports"
    return "file"
}
