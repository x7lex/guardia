"use client";

import { riskZone } from "@/lib/risk";
import RetroIcon from "@/components/retro-icon";

import { useLayoutEffect, useRef } from "react";

export interface Report {
  gemini_review?: {
    status: string;
    review?: string;
    model?: string;
    reason?: string;
    verdict?: string;
    assessment_type?: string;
  };
  reputation?: {
    status: string;
    provider: string;
    reason: string;
    sha256: string;
    checked_at?: string;
  };
  analysis: {
    file: {
      file_name: string;
      file_size: number;
      sha256: string;
      format: string;
      machine: string;
      entry_point: string;
      section_count: number;
      sections: {
        name: string;
        virtual_address: string;
        virtual_size: number;
        raw_size: number;
        entropy: number;
        executable: boolean;
      }[];
    };

    imports: {
      library_count: number;
      function_count: number;
      libraries: {
        name: string;
        functions: string[];
      }[];
    };

    signature: {
      signed: boolean;
      integrity: string;
      known_ca: boolean;
    };

    suspicious_instructions: {
      count: number;
      instructions: string[];
    };
  };

  risk_assessment: {
    model_version?: string;
    signature_state?: string;
    heuristic?: { points: number; level: string; uncapped_score: number };
    decision?: {
      source: string;
      override: {
        type: string;
        provider: string;
        reason: string;
        sha256: string;
      } | null;
      positive_reputation_discount: number;
    };
    file_name: string;
    sha256: string;

    risk: {
      points: number;
      score?: string;
      coverage_limited?: boolean;
      level: string;
      verdict?: string;
      confidence?: number;
      threat_points?: number;
      uncertainty_floor?: number;
      uncertainty_contribution?: number;
    };

    visibility?: {
      level: string;
      score: number;
      reasons: { id: string; reason: string; ceiling: number }[];
    };
    trust?: {
      signature_integrity: string;
      publisher: string | null;
      publisher_verified: boolean;
      chain_trust: string;
      revocation: string;
    };
    context?: { likely_role: string; confidence: number };
    diagnostics?: { limitations?: string[] };

    reasons: {
      reason: string;
      points: number;
      instructions?: string[];
    }[];
  };
}

interface ReportMarkerProps {
  filePath: string;
  report: Report;

  x: number;
  y: number;
  scale: number;

  compact?: boolean;
  onMeasure: (id: string, width: number, height: number) => void;

  onDragStart: () => void;
  onDragMove: (x: number, y: number) => void;
  onDragEnd: (vx: number, vy: number) => void;

  /*
   * IMPORTANT:
   *
   * The marker now sends its DOMRect to the parent.
   * This tells the Genie effect exactly where the
   * window should come out of.
   */
  onOpen: (rect: DOMRect) => void;
}

export function riskAppearance(level: string, points?: number) {
  const zone = riskZone(level, points);
  if (zone === "safe") {
    return {
      color: "#287044",
      background: "#fff9e6",
      header: "#f6e8d5",
      label: "FEW INDICATORS",
      icon: "✓",
    };
  }
  if (zone === "unsafe") {
    return {
      color: "#b32635",
      background: "#fff9e6",
      header: "#f6e8d5",
      label: "HIGH RISK",
      icon: "!",
    };
  }
  return {
    color: "#956014",
    background: "#fff9e6",
    header: "#f6e8d5",
    label: level.toLowerCase() === "inconclusive" ? "INCONCLUSIVE" : "REVIEW",
    icon: "!",
  };
}

export function riskColor(level: string, points?: number) {
  return riskAppearance(level, points).color;
}

export const MARKER_HALF_SIZE = {
  normal: {
    x: 125,
    y: 65,
  },

  compact: {
    x: 90,
    y: 36,
  },
};

export default function ReportMarker({
  filePath,
  report,
  x,
  y,
  scale,
  compact = false,
  onDragStart,
  onDragMove,
  onDragEnd,
  onOpen,
  onMeasure,
}: ReportMarkerProps) {
  const markerRef = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const element = markerRef.current;
    if (!element) return;
    const measure = () =>
      onMeasure(filePath, element.offsetWidth, element.offsetHeight);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => observer.disconnect();
  }, [filePath, compact, onMeasure]);

  const dragging = useRef(false);
  const moved = useRef(false);

  const offset = useRef({
    x: 0,
    y: 0,
  });

  const lastPos = useRef({
    x: 0,
    y: 0,
  });

  const lastDelta = useRef({
    x: 0,
    y: 0,
  });

  function handlePointerDown(e: React.PointerEvent) {
    dragging.current = true;
    moved.current = false;

    offset.current = {
      x: e.clientX - x,
      y: e.clientY - y,
    };

    lastPos.current = {
      x: e.clientX,
      y: e.clientY,
    };

    lastDelta.current = {
      x: 0,
      y: 0,
    };

    e.currentTarget.setPointerCapture(e.pointerId);

    onDragStart();
  }

  function handlePointerMove(e: React.PointerEvent) {
    if (!dragging.current) {
      return;
    }

    const dx = e.clientX - lastPos.current.x;

    const dy = e.clientY - lastPos.current.y;

    /*
     * Don't treat a microscopic pointer movement
     * as a drag.
     */
    if (Math.abs(dx) > 1 || Math.abs(dy) > 1) {
      moved.current = true;
    }

    const nx = e.clientX - offset.current.x;

    const ny = e.clientY - offset.current.y;

    lastDelta.current = {
      x: dx,
      y: dy,
    };

    lastPos.current = {
      x: e.clientX,
      y: e.clientY,
    };

    onDragMove(nx, ny);
  }

  function handlePointerUp(e: React.PointerEvent) {
    dragging.current = false;

    try {
      e.currentTarget.releasePointerCapture(e.pointerId);
    } catch {}

    if (!moved.current) {
      /*
       * THIS is what connects the modal animation
       * to the actual marker.
       */
      if (markerRef.current) {
        onOpen(markerRef.current.getBoundingClientRect());
      }

      onDragEnd(0, 0);

      return;
    }

    onDragEnd(lastDelta.current.x * 0.6, lastDelta.current.y * 0.6);
  }

  const { risk, reasons } = report.risk_assessment;

  const { file, signature, suspicious_instructions } = report.analysis;

  const appearance = riskAppearance(risk.verdict ?? risk.level, risk.points);
  const safe = appearance.label === "FEW INDICATORS";
  const color = appearance.color;
  const statusText = appearance.label;

  /*
   * ========================================================
   * COMPACT MARKER
   * ========================================================
   */

  if (compact) {
    const half = MARKER_HALF_SIZE.compact;

    return (
      <div
        ref={markerRef}
        title={`${filePath} — ${statusText}`}
        style={{
          position: "fixed",

          left: x,

          top: y,

          width: half.x * 2,

          touchAction: "none",

          userSelect: "none",

          zIndex: 20,

          transform: `translate(-50%, -50%) scale(${scale})`,

          transformOrigin: "center center",

          fontFamily: "Tahoma, Verdana, sans-serif",
        }}
      >
        <div
          className="report-drag-handle"
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerCancel={() => {
            dragging.current = false;
            onDragEnd(0, 0);
          }}
          onPointerUp={handlePointerUp}
          style={{
            background: appearance.background,

            border: `3px ridge ${color}`,

            borderRadius: 2,

            padding: "8px 10px",

            boxShadow:
              "inset 1px 1px #fffdf5, inset -1px -1px #9a858b, 2px 3px 0 #70535f50",
          }}
        >
          <div
            className="marker-compact-title"
            style={{
              fontSize: 11,
              fontWeight: "bold",

              color: "#6b2d63",

              overflow: "hidden",

              textOverflow: "ellipsis",

              whiteSpace: "nowrap",

              marginBottom: 5,
            }}
          >
            <RetroIcon name="file" size={12} /> {file.file_name}
          </div>

          <div
            style={{
              display: "flex",

              alignItems: "center",

              justifyContent: "space-between",
            }}
          >
            <div
              style={{
                display: "flex",

                alignItems: "center",

                gap: 5,
              }}
            >
              <div
                style={{
                  width: 7,
                  height: 7,

                  borderRadius: "50%",

                  background: "#9c7b8d",
                }}
              />

              <span
                style={{
                  fontSize: 10,

                  fontWeight: "bold",

                  color,
                }}
              >
                {statusText}
              </span>
            </div>

            <span
              style={{
                fontSize: 13,

                fontWeight: "bold",

                color,
              }}
            >
              {risk.points}
              /10
            </span>
          </div>
        </div>
      </div>
    );
  }

  /*
   * ========================================================
   * NORMAL MARKER
   * ========================================================
   */

  const half = MARKER_HALF_SIZE.normal;

  return (
    <div
      ref={markerRef}
      title={`${filePath} — ${statusText}`}
      style={{
        position: "fixed",

        left: x,

        top: y,

        width: half.x * 2,

        touchAction: "none",

        zIndex: 20,

        userSelect: "none",

        transform: `translate(-50%, -50%) scale(${scale})`,

        transformOrigin: "center center",

        fontFamily: "Tahoma, Verdana, sans-serif",
      }}
    >
      <div
        className="report-drag-handle"
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerCancel={() => {
          dragging.current = false;
          onDragEnd(0, 0);
        }}
        onPointerUp={handlePointerUp}
        style={{
          background: appearance.background,

          border: `3px ridge ${color}`,

          borderRadius: 2,

          overflow: "hidden",

          boxShadow:
            "inset 1px 1px #fffdf5, inset -1px -1px #9a858b, 3px 4px 0 #70535f50",
        }}
      >
        {/* HEADER */}

        <div
          className="marker-titlebar"
          style={{
            display: "flex",

            alignItems: "center",

            justifyContent: "space-between",

            gap: 8,

            padding: "7px 10px",

            background: appearance.header,

            borderBottom: `3px ridge ${color}`,
          }}
        >
          <RetroIcon name="file" size={14} />
          <span
            style={{
              fontWeight: "bold",

              color: "#6b2d63",

              fontSize: 12,

              overflow: "hidden",

              textOverflow: "ellipsis",

              whiteSpace: "nowrap",

              maxWidth: 150,
            }}
          >
            {file.file_name}
          </span>

          <span
            style={{
              display: "flex",

              alignItems: "center",

              gap: 4,

              fontSize: 10,

              fontWeight: "bold",

              color,
              border: `1px solid ${color}`,
              background: "#fff9e6",

              borderRadius: 2,

              padding: "2px 7px",

              whiteSpace: "nowrap",
            }}
          >
            {statusText}
          </span>
        </div>

        <div style={{ padding: "8px 10px" }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              marginBottom: 5,
              fontSize: 11,
              color,
            }}
          >
            <span>Triage score</span>
            <strong>{risk.points}/10</strong>
          </div>

          <div
            style={{
              height: 6,

              width: "100%",

              background: "#ead6e3",

              borderRadius: 10,

              overflow: "hidden",
            }}
          >
            <div
              style={{
                height: "100%",

                width: `${Math.max(risk.points * 10, 2)}%`,

                background: "#9c7b8d",

                borderRadius: 10,
              }}
            />
          </div>
        </div>

        {/* DETAILS */}

        <div
          style={{
            padding: "0 10px 8px",

            fontSize: 10,

            color: "#684a60",
          }}
        >
          <div
            style={{
              marginBottom: 3,
            }}
          >
            {risk.verdict === "Inconclusive"
              ? "Visibility limits the assessment"
              : safe
                ? "Few visible indicators"
                : `${reasons.filter((reason) => reason.points > 0).length} scored findings`}
          </div>

          <div
            style={{
              display: "flex",

              gap: 4,

              alignItems: "center",
            }}
          >
            <span
              style={{
                color: signature.signed ? "#4f8a5b" : "#b33a62",

                fontWeight: "bold",
              }}
            >
              {signature.signed ? "✓" : "!"}
            </span>

            <span>{signature.signed ? "Signed" : "Unsigned"}</span>

            {suspicious_instructions.count > 0 && (
              <>
                <span>·</span>

                <span>{suspicious_instructions.count} suspicious</span>
              </>
            )}
          </div>
        </div>

        {!safe && reasons.length > 0 && (
          <div
            style={{
              padding: "6px 10px",

              background: appearance.header,

              borderTop: "1px dashed #c98cc0",

              fontSize: 9,

              color: "#7a3b61",

              overflow: "hidden",

              textOverflow: "ellipsis",

              whiteSpace: "nowrap",
            }}
          >
            ⚠ {reasons[0].reason}
          </div>
        )}

        <div
          style={{
            padding: "4px 10px",

            fontStyle: "italic",

            fontSize: 9,

            color: "#9c4f8f",

            borderTop: "1px dashed #c98cc0",
          }}
        >
          click to inspect · drag & throw
        </div>
      </div>
    </div>
  );
}
