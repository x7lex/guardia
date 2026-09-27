import asyncio
import copy
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import httpx
from fastapi.testclient import TestClient

from backend.api import app
from backend.gemini_review import (
    SYSTEM_INSTRUCTION,
    VERDICTS,
    attach_review,
    independent_evidence,
)
from backend.plain_text import plain_text_review

REPORT = {
    "analysis": {
        "file": {"file_name": "demo.exe"},
        "strings": {"matches": ["untrusted sample"]},
    },
    "risk_assessment": {"risk": {"points": 2, "level": "Low Risk"}},
}
AsyncClient = httpx.AsyncClient


class GeminiReviewTests(unittest.TestCase):
    def setUp(self):
        sleep = patch("backend.gemini_review.asyncio.sleep", new_callable=AsyncMock)
        self.sleep = sleep.start()
        self.addCleanup(sleep.stop)
        self.client = TestClient(app)
        self.env = patch.dict(
            os.environ,
            {"GEMINI_API_KEY": "test-secret", "GEMINI_MODEL": "gemini-3.8-flash"},
        )
        self.env.start()
        self.addCleanup(self.env.stop)

    def call(self, handler, report=REPORT):
        client = AsyncClient(transport=httpx.MockTransport(handler))
        with patch("backend.gemini_review.httpx.AsyncClient", return_value=client):
            return self.client.post("/review", json=report)

    def test_full_json_sent_and_response_returned_without_key(self):
        def handler(request):
            self.assertEqual(request.headers["x-goog-api-key"], "test-secret")
            self.assertNotIn("test-secret", str(request.url))
            body = json.loads(request.content)
            self.assertEqual(
                json.loads(body["contents"][0]["parts"][0]["text"]),
                independent_evidence(REPORT),
            )
            self.assertIn("untrusted", body["systemInstruction"]["parts"][0]["text"])
            return httpx.Response(
                200,
                json={
                    "candidates": [
                        {
                            "finishReason": "STOP",
                            "content": {
                                "parts": [
                                    {"text": "Private reasoning", "thought": True},
                                    {
                                        "text": "I CANNOT CONFIDENTLY SAY THAT\n\nStatic evidence is incomplete."
                                    },
                                ]
                            },
                        }
                    ]
                },
            )

        response = self.call(handler)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["review"],
            "I CANNOT CONFIDENTLY SAY THAT\n\nStatic evidence is incomplete.",
        )
        self.assertNotIn("test-secret", response.text)

    def test_automatic_review_preserves_score_and_sends_only_raw_evidence(self):
        report = copy.deepcopy(REPORT)
        report["gemini_review"] = {"review": "stale opinion"}

        def handler(request):
            body = json.loads(request.content)
            self.assertEqual(
                json.loads(body["contents"][0]["parts"][0]["text"]),
                independent_evidence(REPORT),
            )
            return httpx.Response(
                200,
                json={
                    "candidates": [
                        {
                            "finishReason": "STOP",
                            "content": {
                                "parts": [
                                    {
                                        "text": "USE AT YOUR OWN RISK\n\nCredential access and outbound transfer are concerning."
                                    }
                                ]
                            },
                        }
                    ]
                },
            )

        client = AsyncClient(transport=httpx.MockTransport(handler))
        with patch("backend.gemini_review.httpx.AsyncClient", return_value=client):
            result = asyncio.run(attach_review(report))
        self.assertEqual(result["risk_assessment"], REPORT["risk_assessment"])
        self.assertEqual(result["gemini_review"]["status"], "complete")
        self.assertIn("no Markdown", SYSTEM_INSTRUCTION)
        self.assertIn("independently", SYSTEM_INSTRUCTION)
        self.assertIn("Unsigned is not automatically malicious", SYSTEM_INSTRUCTION)

    def test_request_is_identical_for_opposite_deterministic_scores(self):
        bodies = []

        def handler(request):
            bodies.append(json.loads(request.content))
            return httpx.Response(
                200,
                json={
                    "candidates": [
                        {
                            "finishReason": "STOP",
                            "content": {
                                "parts": [
                                    {
                                        "text": VERDICTS[1]
                                        + "\n\nThe raw evidence is incomplete."
                                    }
                                ]
                            },
                        }
                    ]
                },
            )

        low, high = copy.deepcopy(REPORT), copy.deepcopy(REPORT)
        low["risk_assessment"] = {
            "risk": {"points": 0, "verdict": "Low Risk"},
            "reasons": ["low score bias"],
        }
        high["risk_assessment"] = {
            "risk": {"points": 10, "verdict": "Dangerous"},
            "reasons": ["high score bias"],
        }
        high["gemini_review"] = {"review": "Previous verdict"}
        low["analysis"]["yara"] = high["analysis"]["yara"] = {"status": "disabled"}
        self.assertEqual(self.call(handler, low).status_code, 200)
        self.assertEqual(self.call(handler, high).status_code, 200)
        self.assertEqual(bodies[0], bodies[1])
        sent = json.loads(bodies[0]["contents"][0]["parts"][0]["text"])
        self.assertEqual(sent["analysis"], high["analysis"])
        self.assertNotIn("risk_assessment", sent)
        self.assertNotIn("gemini_review", sent)

    def test_nested_legacy_weights_are_excluded_but_evidence_is_complete(self):
        report = copy.deepcopy(REPORT)
        finding = {
            "id": "credential_exfiltration",
            "family": "credentials",
            "base_points": 8,
            "points": 10,
            "strength": "strong",
            "evidence": {"calls": ["send"], "literal": "score = 10"},
        }
        report["analysis"]["payload_inspection"] = {
            "scripts": [{"findings": [finding]}]
        }
        evidence = independent_evidence(report)
        cleaned = evidence["analysis"]["payload_inspection"]["scripts"][0]["findings"][
            0
        ]
        self.assertNotIn("base_points", cleaned)
        self.assertNotIn("points", cleaned)
        self.assertEqual(cleaned["evidence"], finding["evidence"])
        self.assertEqual(finding["base_points"], 8)

    def test_exact_verdict_contract_and_explanation_required(self):
        for text in (
            "Introduction\n" + VERDICTS[0] + "\nFine.",
            "It is safe.",
            VERDICTS[0],
            VERDICTS[0] + "\n" + VERDICTS[2],
        ):
            response = self.call(
                lambda request, current_text=text: httpx.Response(
                    200,
                    json={
                        "candidates": [
                            {
                                "finishReason": "STOP",
                                "content": {"parts": [{"text": current_text}]},
                            }
                        ]
                    },
                )
            )
            self.assertEqual(response.status_code, 502)
        for verdict in VERDICTS:
            response = self.call(
                lambda request, current_verdict=verdict: httpx.Response(
                    200,
                    json={
                        "candidates": [
                            {
                                "finishReason": "STOP",
                                "content": {
                                    "parts": [
                                        {
                                            "text": current_verdict
                                            + "\n\nEvidence-based explanation."
                                        }
                                    ]
                                },
                            }
                        ]
                    },
                )
            )
            self.assertEqual(response.json()["verdict"], verdict)
            self.assertTrue(response.json()["review"].startswith(verdict + "\n"))

    def test_automatic_review_failure_keeps_deterministic_report(self):
        client = AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(429))
        )
        with patch("backend.gemini_review.httpx.AsyncClient", return_value=client):
            result = asyncio.run(attach_review(copy.deepcopy(REPORT)))
        self.assertEqual(result["risk_assessment"], REPORT["risk_assessment"])
        self.assertEqual(result["gemini_review"]["status"], "unavailable")
        with patch.dict(os.environ, {"GEMINI_API_KEY": "", "API_TOKEN": ""}):
            result = asyncio.run(attach_review(copy.deepcopy(REPORT)))
            self.assertIn("not configured", result["gemini_review"]["reason"])

    def test_markdown_provider_response_is_returned_as_plain_text(self):
        markdown = "# I CANNOT CONFIDENTLY SAY THAT\n\n**Reasonable** score with `risk_assessment.risk.points`.\n\n- *Possible false positive*.\n1. Check [vendor](https://example.org).\n> Keep the score.\n```text\nEvidence remains.\n```"
        response = self.call(
            lambda request: httpx.Response(
                200,
                json={
                    "candidates": [
                        {
                            "finishReason": "STOP",
                            "content": {"parts": [{"text": markdown}]},
                        }
                    ]
                },
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["review"],
            "I CANNOT CONFIDENTLY SAY THAT\n\nReasonable score with risk_assessment.risk.points.\n\nPossible false positive.\nCheck vendor (https://example.org).\nKeep the score.\n\nEvidence remains.",
        )

    def test_plain_evidence_and_paragraphs_are_preserved(self):
        text = "The score is 4.5/10.0. risk_assessment and field_name are field names.\n\nPath: C:\\temp\\_internal_\\sample.exe. 2 * 3 = 6. https://example.org/a_b"
        self.assertEqual(plain_text_review(text), text)
        self.assertEqual(
            plain_text_review("Call `__init__` and inspect `a * b`."),
            "Call __init__ and inspect a * b.",
        )
        self.assertEqual(
            plain_text_review(
                "| Finding | Score |\n| --- | --- |\n| __Unsigned__ | 4.0 |"
            ),
            "Finding; Score\nUnsigned; 4.0",
        )
        self.assertEqual(
            plain_text_review("## Review ##\n- [x] ~~Old~~ finding\n---"),
            "Review\nOld finding",
        )

    def test_quota_and_auth_errors_are_safe_and_actionable(self):
        for status, expected in (
            (402, 402),
            (429, 429),
            (403, 502),
            (404, 502),
            (500, 502),
        ):
            response = self.call(
                lambda request, s=status: httpx.Response(
                    s, json={"error": {"message": "test-secret"}}
                )
            )
            self.assertEqual(response.status_code, expected)
            self.assertNotIn("test-secret", response.text)

    def test_transient_overload_recovers_without_changing_evidence(self):
        attempts = []

        def handler(request):
            attempts.append(json.loads(request.content))
            if len(attempts) < 3:
                return httpx.Response(503, json={"error": {"message": "test-secret"}})
            return httpx.Response(
                200,
                json={
                    "candidates": [
                        {
                            "finishReason": "STOP",
                            "content": {
                                "parts": [
                                    {
                                        "text": "THIS IS PERFECTLY FINE\n\nThe evidence supports a benign assessment."
                                    }
                                ]
                            },
                        }
                    ]
                },
            )

        response = self.call(handler)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["review"],
            "THIS IS PERFECTLY FINE\n\nThe evidence supports a benign assessment.",
        )
        self.assertEqual(len(attempts), 3)
        self.assertTrue(all(body == attempts[0] for body in attempts))
        self.assertEqual(self.sleep.await_count, 2)
        delays = [call.args[0] for call in self.sleep.await_args_list]
        self.assertTrue(1 <= delays[0] <= 1.5)
        self.assertTrue(2 <= delays[1] <= 2.5)

    def test_persistent_overload_returns_clear_503_after_bounded_retries(self):
        calls = []

        def handler(request):
            calls.append(request)
            return httpx.Response(503, json={"error": {"message": "test-secret"}})

        response = self.call(handler)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(len(calls), 3)
        self.assertIn("Google Gemini", response.json()["detail"])
        self.assertNotIn("test-secret", response.text)

    def test_credentials_billing_quota_and_missing_model_are_not_retried(self):
        for s in (400, 401, 402, 403, 404, 429):
            status_val = s
            calls = []

            def handler(request, s_val=status_val, current_calls=calls):
                current_calls.append(request)
                return httpx.Response(s_val)

            self.call(handler)
            self.assertEqual(len(calls), 1)

    def test_blocked_and_truncated_responses_are_not_presented_as_complete(self):
        for data in (
            {"candidates": []},
            {
                "candidates": [
                    {
                        "finishReason": "MAX_TOKENS",
                        "content": {"parts": [{"text": "Partial"}]},
                    }
                ]
            },
        ):
            response = self.call(lambda request, d=data: httpx.Response(200, json=d))
            self.assertEqual(response.status_code, 502)
            self.assertIn("complete review", response.json()["detail"])

    def test_timeout_has_retry_message(self):
        def timeout(request):
            raise httpx.ReadTimeout("timeout", request=request)

        self.assertEqual(self.call(timeout).status_code, 504)

    def test_missing_key_and_api_token_fallback(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": "", "API_TOKEN": ""}):
            self.assertEqual(self.client.post("/review", json=REPORT).status_code, 503)

        def handler(request):
            self.assertEqual(request.headers["x-goog-api-key"], "fallback-secret")
            return httpx.Response(
                200,
                json={
                    "candidates": [
                        {
                            "finishReason": "STOP",
                            "content": {
                                "parts": [
                                    {
                                        "text": "I CANNOT CONFIDENTLY SAY THAT\n\nEvidence is incomplete."
                                    }
                                ]
                            },
                        }
                    ]
                },
            )

        with patch.dict(
            os.environ, {"GEMINI_API_KEY": "", "API_TOKEN": "fallback-secret"}
        ):
            self.assertEqual(self.call(handler).status_code, 200)

    def test_invalid_and_oversize_reports_rejected_before_provider(self):
        for report in (
            None,
            [],
            {},
            {"analysis": []},
            {"analysis": {"file": {}}, "risk_assessment": {}},
        ):
            self.assertEqual(
                self.client.post("/review", json=report).status_code,
                400 if report is not None else 415,
            )
        self.assertEqual(
            self.client.post(
                "/review",
                content="broken",
                headers={"Content-Type": "application/json"},
            ).status_code,
            400,
        )
        with patch("backend.api.MAX_REVIEW_BYTES", 8):
            self.assertEqual(self.client.post("/review", json=REPORT).status_code, 413)
