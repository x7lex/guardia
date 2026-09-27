"""Behavioral regressions for the simple conservative scoring policy."""
import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from backend.risk_score import calculate_risk
from backend.signatures import recognized_issuer
from backend.pe_metadata import overlay_layout
from backend.risk_score import calculate_risk

FIXTURES = Path(__file__).parent / "fixtures" / "reports"


def profile(name):
    return json.loads((FIXTURES / (name + ".json")).read_text())["analysis"]


def ordinary(*apis):
    return {"file": {}, "imports": {"libraries": [{"functions": list(apis)}]},
            "signature": {"integrity": "UNSIGNED"}, "strings": {"matches": {}}}


def score(report):
    return calculate_risk(report)["risk"]["points"]


def signed(report, recognized=True):
    report = copy.deepcopy(report)
    report["signature"] = {"signed": True, "integrity": "VALID", "known_ca": recognized}
    return report


class RiskScoringTests(unittest.TestCase):
    def test_fixture_regressions_and_reconstruction(self):
        for name in ("installer", "packed_application", "opaque_container"):
            result = calculate_risk(profile(name))
            expected = round(min(10, max(0, sum(r["points"] for r in result["reasons"]))), 1)
            self.assertEqual(expected, result["risk"]["points"])
            self.assertNotIn("confidence", result["risk"])
            self.assertNotIn("visibility", result)
        self.assertLess(score(profile("installer")), 1)
        self.assertGreaterEqual(score(profile("packed_application")), 4)
        self.assertGreaterEqual(score(profile("opaque_container")), 4)

    def test_signature_states(self):
        report = ordinary()
        self.assertEqual(score(report), 4)
        self.assertEqual(score(signed(report)), 0)
        self.assertEqual(score(signed(report, False)), 0.5)
        report["signature"].update(integrity="INVALID", known_ca=True)
        self.assertEqual(score(report), 5)
        report["signature"]["integrity"] = "UNKNOWN"
        self.assertEqual(score(report), 3)
        report.pop("signature")
        self.assertEqual(score(report), 3)

    def test_issuer_detection_and_spoofed_subject(self):
        self.assertTrue(recognized_issuer("C=US, CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"))
        self.assertFalse(recognized_issuer("CN=Not DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"))
        report = signed(ordinary(), False)
        report["signature"]["publishers"] = [{"subject": "CN=Google LLC", "issuer": "CN=Unknown"}]
        self.assertEqual(score(report), 0.5)
        report["signature"]["publishers"] = profile("installer")["signature"]["publishers"]
        self.assertEqual(score(report), 0)
        report["signature"]["integrity"] = "INVALID"
        self.assertEqual(score(report), 5)

    def test_import_combinations_and_signing_discount(self):
        for api in ("CryptUnprotectData", "WinHttpSendRequest", "OpenProcess", "IsDebuggerPresent"):
            self.assertEqual(score(ordinary(api)), 4)
        pair = ordinary("CryptUnprotectData", "WinHttpSendRequest")
        triple = ordinary("CryptUnprotectData", "WinHttpSendRequest", "OpenProcess")
        self.assertGreater(score(pair), 6)
        self.assertGreaterEqual(score(triple), 8)
        self.assertLess(score(signed(triple)), 1)
        self.assertGreater(score(signed(triple, False)), score(signed(triple)))

    def test_strong_chains_override_trust(self):
        injection = ordinary("OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
        self.assertGreaterEqual(score(signed(injection)), 6)
        self.assertEqual(score(injection), 10)
        credentials = ordinary("CryptUnprotectData", "ReadFile", "WinHttpSendRequest")
        credentials["strings"]["matches"] = {"browser_path": ["Google/Chrome/User Data"], "browser_database": ["Login Data"]}
        self.assertGreaterEqual(score(signed(credentials)), 8)

    def test_independent_families_amplify_and_duplicate_findings_do_not(self):
        report = ordinary("OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
        result = calculate_risk(signed(report))
        feature = next(r for r in result["reasons"] if r["id"] == "injection_chain")
        report["payload_inspection"] = {"status": "inspected", "archive": {"status": "inspected", "scripts": [{"status": "inspected", "findings": [feature, copy.deepcopy(feature)]}]}}
        self.assertEqual(score(signed(report)), result["risk"]["points"])
        report["imports"]["libraries"][0]["functions"] += ["RegSetValueExW"]
        report["strings"]["matches"]["autorun"] = ["Software/Microsoft/Windows/CurrentVersion/Run"]
        self.assertGreater(calculate_risk(signed(report))["diagnostics"]["category_factor"], 1)
        self.assertGreater(score(signed(report)), result["risk"]["points"])

    def test_cpu_is_bounded_and_repetition_is_not_weighted(self):
        report = ordinary()
        report["disassembly"] = {"mnemonic_counts": {"mov": 10000, "xor": 10000, "int3": 10000}}
        self.assertEqual(score(report), 4)
        report["disassembly"]["mnemonic_counts"].update(cpuid=1, rdtsc=1, syscall=1, rdmsr=1)
        self.assertEqual(score(report), 4.8)
        before = score(report)
        report["disassembly"]["mnemonic_counts"].update(cpuid=10000, rdtsc=10000)
        self.assertEqual(score(report), before)
        self.assertLessEqual(score(signed(report)), 0.1)

    def test_identity_order_counts_and_opacity_do_not_drive_score(self):
        report = profile("installer")
        before = score(report)
        report["file"].update(file_name="malware.exe", sha256="0" * 64)
        report["signature"]["publishers"][0]["subject"] = "CN=Unknown"
        report["imports"]["libraries"].reverse()
        report["imports"]["libraries"].append({"functions": ["OrdinaryFunction"] * 1000})
        report["strings"]["matches"]["url"] = ["http://example.org"] * 1000
        report["file"]["overlay"]["payload_fraction"] = 0.99
        self.assertEqual(score(report), before)

    def test_certificate_bytes_excluded_but_payload_after_certificate_kept(self):
        layout = overlay_layout(2000, 1000, 1100, 400)
        self.assertEqual(layout["certificate_bytes"], 400)
        self.assertEqual(layout["payload_bytes"], 600)
        self.assertEqual(overlay_layout(2000, 1000, 1500, 1000)["certificate_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
