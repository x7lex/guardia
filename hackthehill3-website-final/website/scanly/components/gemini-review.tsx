"use client";

import { useEffect, useId, useRef, useState } from "react";
import type { Report } from "@/components/report-marker";

type Review = { review: string; model: string; assessment_type?: string };

export default function GeminiReview({ report }: { report: Report }) {
  const id = useId();
  const saved = report.gemini_review;
  const [open, setOpen] = useState(Boolean(saved));
  const [result, setResult] = useState<Review | null>(
    saved?.status === "complete" && saved.review && saved.model
      ? {
          review: saved.review,
          model: saved.model,
          assessment_type: saved.assessment_type,
        }
      : null,
  );
  const [loading, setLoading] = useState(false);
  const [billingRequired, setBillingRequired] = useState(false);
  const [error, setError] = useState(
    saved?.status === "unavailable"
      ? (saved.reason ?? "Review unavailable")
      : "",
  );
  const controller = useRef<AbortController | null>(null);

  useEffect(
    () => () => {
      controller.current?.abort();
      controller.current = null;
    },
    [],
  );

  async function review() {
    if (controller.current) return;
    const request = new AbortController();
    controller.current = request;
    setOpen(true);
    setLoading(true);
    setError("");
    setBillingRequired(false);
    try {
      const response = await fetch("/api/review", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(report),
        signal: request.signal,
      });
      const body = await response.json().catch(() => null);
      if (!request.signal.aborted && response.status === 402)
        setBillingRequired(true);
      if (!response.ok)
        throw new Error(
          typeof body?.detail === "string"
            ? body.detail
            : "Gemini review failed. Please try again.",
        );
      if (
        typeof body?.review !== "string" ||
        !body.review.trim() ||
        typeof body?.model !== "string"
      ) {
        throw new Error(
          "The review service returned an invalid response. Please try again.",
        );
      }
      if (!request.signal.aborted) setResult(body);
    } catch (cause) {
      if (!request.signal.aborted)
        setError(
          cause instanceof Error
            ? cause.message
            : "Could not load the Gemini review.",
        );
    } finally {
      if (controller.current === request) {
        controller.current = null;
        setLoading(false);
      }
    }
  }

  function cancel() {
    controller.current?.abort();
    controller.current = null;
    setLoading(false);
    setError("Review cancelled. You can try again when ready.");
  }

  return (
    <section
      className="rounded-sm border-2 border-[#cbaa9c] bg-[#fffdf5] p-3"
      aria-label="Gemini review"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <button
          type="button"
          className="retro-button px-4"
          aria-expanded={open}
          aria-controls={id}
          onClick={() => {
            if (open) setOpen(false);
            else if (!result && !loading) void review();
            else setOpen(true);
          }}
        >
          {open
            ? "Hide Gemini review"
            : result || loading
              ? "Open Gemini review"
              : "✦ Review with Gemini"}
        </button>
        <span className="text-xs text-[#805775]">Powered by Gemini</span>
      </div>
      <p className="mt-2 text-xs text-[#805775]">
        Independent Gemini assessment: sends raw static evidence and hash
        reputation. The local score and verdict are excluded. Gemini may
        disagree with the engine.
      </p>
      <div id={id} hidden={!open} className="mt-3 text-sm text-[#4a2b45]">
        {loading && (
          <div role="status" aria-live="polite">
            <p>Gemini is reviewing the scan report…</p>
            <button
              type="button"
              className="retro-button mt-2 px-3"
              onClick={cancel}
            >
              Cancel review
            </button>
          </div>
        )}
        {error && (
          <div role="alert">
            <p>{error}</p>
            {billingRequired && (
              <a
                className="mt-2 block underline"
                href="https://ai.studio/projects"
                target="_blank"
                rel="noopener noreferrer"
              >
                Manage Gemini billing ↗
              </a>
            )}
            <button
              type="button"
              className="retro-button mt-2 px-3"
              onClick={() => void review()}
            >
              Retry review
            </button>
          </div>
        )}
        {result && (
          <div aria-live="polite">
            <div className="whitespace-pre-wrap break-words leading-relaxed">
              {result.review}
            </div>
            <p className="mt-3 text-xs text-[#805775]">
              {result.model} ·{" "}
              {result.assessment_type === "independent_static"
                ? "Independent assessment of the raw evidence; does not change the engine score."
                : "Legacy review, which may have used the old score. Request a new assessment for independent analysis."}
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
