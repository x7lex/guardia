import json
import asyncio
import copy
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import httpx
from fastapi.testclient import TestClient

from backend.api import app
from backend.gemini_review import attach_review, SYSTEM_INSTRUCTION
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
                json.loads(body["contents"][0]["parts"][0]["text"]), REPORT
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
                                    {"text": "Assessment: needs review."},
                                ]
                            },
                        }
                    ]
                },
            )

        response = self.call(handler)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["review"], "Assessment: needs review.")
        self.assertNotIn("test-secret", response.text)

    def test_automatic_review_preserves_score_and_sends_only_raw_evidence(self):
        report = copy.deepcopy(REPORT)
        report["gemini_review"] = {"review": "stale opinion"}
        def handler(request):
            body = json.loads(request.content)
            self.assertEqual(json.loads(body["contents"][0]["parts"][0]["text"]), REPORT)
            return httpx.Response(200, json={"candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": "The score seems too low."}]}}]})
        client = AsyncClient(transport=httpx.MockTransport(handler))
        with patch("backend.gemini_review.httpx.AsyncClient", return_value=client):
            result = asyncio.run(attach_review(report))
        self.assertEqual(result["risk_assessment"], REPORT["risk_assessment"])
        self.assertEqual(result["gemini_review"]["status"], "complete")
        self.assertIn("no Markdown", SYSTEM_INSTRUCTION)
        self.assertIn("false positives", SYSTEM_INSTRUCTION)
        self.assertIn("false negatives", SYSTEM_INSTRUCTION)

    def test_automatic_review_failure_keeps_deterministic_report(self):
        client = AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(429)))
        with patch("backend.gemini_review.httpx.AsyncClient", return_value=client):
            result = asyncio.run(attach_review(copy.deepcopy(REPORT)))
        self.assertEqual(result["risk_assessment"], REPORT["risk_assessment"])
        self.assertEqual(result["gemini_review"]["status"], "unavailable")
        with patch.dict(os.environ, {"GEMINI_API_KEY": "", "API_TOKEN": ""}):
            result = asyncio.run(attach_review(copy.deepcopy(REPORT)))
            self.assertIn("not configured", result["gemini_review"]["reason"])

    def test_markdown_provider_response_is_returned_as_plain_text(self):
        markdown = "# Assessment\n\n**Reasonable** score with `risk_assessment.risk.points`.\n\n- *Possible false positive*.\n1. Check [vendor](https://example.org).\n> Keep the score.\n```text\nEvidence remains.\n```"
        response = self.call(lambda request: httpx.Response(200, json={"candidates": [{
            "finishReason": "STOP", "content": {"parts": [{"text": markdown}]}}]}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["review"], "Assessment\n\nReasonable score with risk_assessment.risk.points.\n\nPossible false positive.\nCheck vendor (https://example.org).\nKeep the score.\n\nEvidence remains.")

    def test_plain_evidence_and_paragraphs_are_preserved(self):
        text = "The score is 4.5/10.0. risk_assessment and field_name are field names.\n\nPath: C:\\temp\\_internal_\\sample.exe. 2 * 3 = 6. https://example.org/a_b"
        self.assertEqual(plain_text_review(text), text)
        self.assertEqual(plain_text_review("Call `__init__` and inspect `a * b`."), "Call __init__ and inspect a * b.")
        self.assertEqual(plain_text_review("| Finding | Score |\n| --- | --- |\n| __Unsigned__ | 4.0 |"), "Finding; Score\nUnsigned; 4.0")
        self.assertEqual(plain_text_review("## Review ##\n- [x] ~~Old~~ finding\n---"), "Review\nOld finding")

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
                            "content": {"parts": [{"text": "Review"}]},
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
