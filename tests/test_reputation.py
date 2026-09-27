"""Hash-only wire contracts and reputation overrides are independent of signing."""

import asyncio
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import httpx

from backend.assessment import build_report
from backend.reputation import classify_response, lookup_hash
from backend.risk_score import calculate_risk

HASH = "a" * 64
OTHER = "b" * 64
AsyncClient = httpx.AsyncClient


def vt(malicious=0, undetected=40, reputation=0, votes=None):
    return {
        "data": {
            "type": "file",
            "id": HASH,
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "undetected": undetected,
                },
                "reputation": reputation,
                "total_votes": votes or {},
            },
        }
    }


class ReputationTests(unittest.TestCase):
    def call(self, handler, provider="malwarebazaar", sha256=HASH):
        client = AsyncClient(transport=httpx.MockTransport(handler))
        with (
            patch.dict(
                os.environ,
                {
                    "REPUTATION_PROVIDER": provider,
                    "MALWAREBAZAAR_API_KEY": "secret-key",
                    "VIRUSTOTAL_API_KEY": "secret-key",
                },
            ),
            patch("backend.reputation.httpx.AsyncClient", return_value=client),
        ):
            return asyncio.run(lookup_hash(sha256))

    def test_malwarebazaar_sends_only_hash_and_checks_exact_match(self):
        def handler(request):
            self.assertEqual(str(request.url), "https://mb-api.abuse.ch/api/v1/")
            self.assertEqual(request.headers["Auth-Key"], "secret-key")
            self.assertEqual(
                parse_qs(request.content.decode()),
                {"query": ["get_info"], "hash": [HASH]},
            )
            return httpx.Response(
                200,
                json={
                    "query_status": "ok",
                    "data": [{"sha256_hash": HASH, "signature": "TestFamily"}],
                },
            )

        self.assertEqual(self.call(handler)["status"], "known_malicious")
        mismatch = self.call(
            lambda request: httpx.Response(
                200, json={"query_status": "ok", "data": [{"sha256_hash": OTHER}]}
            )
        )
        self.assertEqual(mismatch["status"], "unavailable")

    def test_virustotal_does_not_upload_and_requires_strong_consensus(self):
        def handler(request):
            self.assertEqual(request.method, "GET")
            self.assertEqual(
                str(request.url), "https://www.virustotal.com/api/v3/files/" + HASH
            )
            self.assertEqual(request.content, b"")
            return httpx.Response(200, json=vt(20, 20))

        self.assertEqual(self.call(handler, "virustotal")["status"], "known_malicious")
        for body in (vt(0, 50), vt(1, 50), vt(9, 0), vt(10, 90)):
            self.assertEqual(
                classify_response(HASH, "virustotal", body)["status"], "unknown"
            )
        self.assertEqual(
            classify_response(HASH, "virustotal", vt(10, 30))["status"],
            "known_malicious",
        )

    def test_dual_use_or_pup_consensus_is_not_confirmed_malware(self):
        body = vt(30, 10)
        body["data"]["attributes"]["popular_threat_classification"] = {
            "suggested_threat_label": "hacktool.game",
            "popular_threat_category": [{"value": "pua"}],
        }
        result = classify_response(HASH, "virustotal", body)
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["evidence"]["potentially_unwanted_or_dual_use"])

    def test_disabled_missing_key_outage_quota_invalid_data_and_unknown_are_safe(self):
        with (
            patch.dict(os.environ, {"REPUTATION_PROVIDER": "disabled"}),
            patch("backend.reputation.httpx.AsyncClient") as client,
        ):
            self.assertEqual(asyncio.run(lookup_hash(HASH))["status"], "disabled")
            client.assert_not_called()
        with patch.dict(
            os.environ,
            {"REPUTATION_PROVIDER": "malwarebazaar", "MALWAREBAZAAR_API_KEY": ""},
        ):
            self.assertEqual(asyncio.run(lookup_hash(HASH))["status"], "unavailable")
        for c, expected in (
            (429, "rate_limited"),
            (503, "unavailable"),
            (401, "unavailable"),
        ):
            c_val = c
            result = self.call(
                lambda request, code=c_val: httpx.Response(
                    code, json={"secret": "secret-key"}
                )
            )
            self.assertEqual(result["status"], expected)
            self.assertNotIn("secret-key", json.dumps(result))

        def timeout(request):
            raise httpx.ReadTimeout("secret-key", request=request)

        self.assertEqual(self.call(timeout)["status"], "unavailable")
        for b in ([], None, {"query_status": "ok", "data": []}):
            body_val = b
            self.assertEqual(
                self.call(
                    lambda request, b_val=body_val: httpx.Response(200, json=b_val)
                )["status"],
                "unavailable",
            )
        self.assertEqual(
            self.call(
                lambda request: httpx.Response(
                    200, json={"query_status": "hash_not_found"}
                )
            )["status"],
            "unknown",
        )
        self.assertEqual(
            self.call(lambda request: httpx.Response(404), "virustotal")["status"],
            "unknown",
        )

    def test_known_malicious_override_survives_every_signature_state(self):
        rep = classify_response(
            HASH,
            "malwarebazaar",
            {"query_status": "ok", "data": [{"sha256_hash": HASH}]},
        )
        for integrity in ("VALID", "UNSIGNED", "INVALID", "UNKNOWN"):
            for trusted in (False, True):
                analysis = {
                    "file": {"sha256": HASH},
                    "signature": {
                        "integrity": integrity,
                        "known_ca": trusted,
                        "chain_trust": "TRUSTED",
                    },
                }
                result = calculate_risk(analysis, reputation=rep)
                self.assertEqual(result["risk"]["points"], 10)
                self.assertEqual(result["risk"]["classification"], "known_malicious")
                self.assertEqual(result["decision"]["source"], "reputation_override")
                self.assertEqual(
                    result["heuristic"]["points"],
                    calculate_risk(analysis)["risk"]["points"],
                )
        rep["sha256"] = OTHER
        self.assertIsNone(
            calculate_risk(analysis, reputation=rep)["decision"]["override"]
        )

    def test_positive_reputation_corroborates_unsigned_without_canceling_strong_evidence(
        self,
    ):
        rep = classify_response(
            HASH, "virustotal", vt(0, 40, 100, {"harmless": 10, "malicious": 0})
        )
        self.assertEqual(rep["status"], "reputable")
        analysis = {
            "file": {"sha256": HASH},
            "signature": {"integrity": "UNSIGNED"},
            "yara": {
                "status": "complete",
                "rules_sha256": OTHER,
                "matches": [
                    {"rule": "vetted", "meta": {"malware": True, "confidence": "high"}}
                ],
            },
        }
        result = calculate_risk(analysis, reputation=rep)
        self.assertEqual(result["risk"]["points"], 10)
        analysis.pop("yara")
        self.assertEqual(calculate_risk(analysis, reputation=rep)["risk"]["points"], 2)
        analysis["disassembly"] = {"mnemonic_counts": {"cpuid": 1}}
        result = calculate_risk(analysis, reputation=rep)
        self.assertGreater(result["decision"]["positive_reputation_discount"], 0)
        self.assertGreaterEqual(result["risk"]["points"], 2)
        analysis["signature"]["integrity"] = "INVALID"
        self.assertGreaterEqual(
            calculate_risk(analysis, reputation=rep)["risk"]["points"], 5
        )

    def test_malformed_saved_reputation_cannot_override_or_break_local_score(self):
        analysis = {"file": {"sha256": HASH}, "signature": {"integrity": "UNSIGNED"}}
        rep = classify_response(HASH, "virustotal", vt(20, 20))
        for evidence in (
            None,
            [],
            {**rep["evidence"], "stats": None},
            {**rep["evidence"], "stats": []},
        ):
            result = calculate_risk(analysis, reputation={**rep, "evidence": evidence})
            self.assertEqual(result["risk"]["points"], 4)
            self.assertEqual(result["decision"]["source"], "heuristics")

    def test_pipeline_keeps_three_namespaces_separate(self):
        with patch.dict(
            os.environ,
            {"REPUTATION_PROVIDER": "disabled", "GEMINI_API_KEY": "", "API_TOKEN": ""},
        ):
            report = asyncio.run(build_report({"file": {"sha256": HASH}}))
        self.assertEqual(report["reputation"]["status"], "disabled")
        self.assertEqual(report["gemini_review"]["status"], "unavailable")
        self.assertIn("heuristic", report["risk_assessment"])


if __name__ == "__main__":
    unittest.main()
