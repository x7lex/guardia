import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import httpx
from fastapi.testclient import TestClient
from backend.api import app

REPORT = {"analysis": {"file": {"file_name": "demo.exe"}, "strings": {"matches": ["untrusted sample"]}},
          "risk_assessment": {"risk": {"points": 2, "level": "Low Risk"}}}
AsyncClient = httpx.AsyncClient


class GeminiReviewTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.env = patch.dict(os.environ, {"GEMINI_API_KEY": "test-secret", "GEMINI_MODEL": "gemini-3.8-flash"})
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
            self.assertEqual(json.loads(body["contents"][0]["parts"][0]["text"]), REPORT)
            self.assertIn("untrusted", body["systemInstruction"]["parts"][0]["text"])
            return httpx.Response(200, json={"candidates": [{"finishReason": "STOP", "content": {"parts": [
                {"text": "Private reasoning", "thought": True}, {"text": "Assessment: needs review."}]}}]})
        response = self.call(handler)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["review"], "Assessment: needs review.")
        self.assertNotIn("test-secret", response.text)

    def test_quota_and_auth_errors_are_safe_and_actionable(self):
        for status, expected in ((402, 402), (429, 429), (403, 502), (404, 502), (500, 502)):
            response = self.call(lambda request: httpx.Response(status, json={"error": {"message": "test-secret"}}))
            self.assertEqual(response.status_code, expected)
            self.assertNotIn("test-secret", response.text)

    def test_blocked_and_truncated_responses_are_not_presented_as_complete(self):
        for data in ({"candidates": []}, {"candidates": [{"finishReason": "MAX_TOKENS", "content": {"parts": [{"text": "Partial"}]}}]}):
            response = self.call(lambda request: httpx.Response(200, json=data))
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
            return httpx.Response(200, json={"candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": "Review"}]}}]})
        with patch.dict(os.environ, {"GEMINI_API_KEY": "", "API_TOKEN": "fallback-secret"}):
            self.assertEqual(self.call(handler).status_code, 200)

    def test_invalid_and_oversize_reports_rejected_before_provider(self):
        for report in (None, [], {}, {"analysis": []}, {"analysis": {"file": {}}, "risk_assessment": {}}):
            self.assertEqual(self.client.post("/review", json=report).status_code, 400 if report is not None else 415)
        self.assertEqual(self.client.post("/review", content="broken", headers={"Content-Type": "application/json"}).status_code, 400)
        with patch("backend.api.MAX_REVIEW_BYTES", 8):
            self.assertEqual(self.client.post("/review", json=REPORT).status_code, 413)
