"""Property regressions from the three complete supplied reports and counterexamples."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from backend.risk_score import calculate_risk
from backend.pe_metadata import overlay_layout

FIXTURES = Path(__file__).parent / "fixtures" / "reports"


def profile(name):
    return json.loads((FIXTURES / (name + ".json")).read_text())["analysis"]


def ordinary(*apis):
    return {"file": {"file_size": 4096, "sections": [{"name": ".text", "raw_size": 2048, "entropy": 5.5, "executable": True, "writable": False}],
                     "overlay": {"payload_bytes": 0, "payload_fraction": 0}},
            "imports": {"libraries": [{"name": "library", "functions": list(apis) or ["ExitProcess"]}]},
            "strings": {"matches": {}}, "signature": {"integrity": "UNSIGNED"}, "coverage": {"limitations": []}}


def add_apis(report, *apis):
    report["imports"]["libraries"].append({"name": "extra", "functions": list(apis)})


class RiskArchitectureTests(unittest.TestCase):
    def test_full_report_regressions(self):
        installer = calculate_risk(profile("installer"))
        for name in ("packed_application", "opaque_container"):
            result = calculate_risk(profile(name))
            self.assertEqual(result["risk"]["verdict"], "Inconclusive")
            self.assertEqual(result["visibility"]["level"], "SEVERELY_LIMITED")
            self.assertLess(result["risk"]["points"], 4)
            self.assertGreater(result["risk"]["points"], installer["risk"]["points"])
            self.assertGreater(result["risk"]["uncertainty_contribution"], 0)
        self.assertEqual(installer["context"]["likely_role"], "installer_updater")
        self.assertEqual(installer["trust"]["signature_integrity"], "VALID")
        self.assertEqual(installer["trust"]["publisher"], "Google LLC")
        self.assertFalse(installer["trust"]["publisher_verified"])
        persistence = next(r for r in installer["reasons"] if r["id"] == "autorun_write")
        self.assertLess(persistence["points"], persistence["nominal_points"])

    def test_rwx_and_hidden_payload_remain_auditable_without_threat_points(self):
        packed = calculate_risk(profile("packed_application"))
        rwx = next(r for r in packed["reasons"] if r["id"] == "rwx_sections")
        self.assertEqual(set(rwx["evidence"]["sections"]), {"UPX0", "UPX1"})
        self.assertEqual(rwx["points"], 0)
        hidden = calculate_risk(profile("opaque_container"))
        payload = next(r for r in hidden["visibility"]["reasons"] if r["id"] == "opaque_appended_payload")
        self.assertGreater(payload["evidence"]["payload_fraction"], 0.96)

    def test_names_hashes_and_publisher_names_do_not_drive_classification(self):
        for name in ("installer", "packed_application", "opaque_container"):
            original = profile(name)
            renamed = copy.deepcopy(original)
            renamed["file"].update(file_name="arbitrary.dll", file_path="/other/path", sha256="0" * 64)
            for publisher in renamed["signature"].get("publishers", []):
                publisher["subject"] = "CN=Unfamiliar Software Ltd"
            before, after = calculate_risk(original), calculate_risk(renamed)
            self.assertEqual(before["risk"], after["risk"])
            self.assertEqual(before["visibility"], after["visibility"])

    def test_counts_dynamic_resolution_and_disassembly_are_not_threats(self):
        report = ordinary("LoadLibraryA", "GetProcAddress", "IsDebuggerPresent", "NtQueryInformationProcess")
        report["strings"]["matches"] = {"url": ["https://example.org"] * 500, "domain": ["example.org"] * 500, "browser_database": ["cookies"] * 100}
        report["disassembly"] = {"mnemonic_counts": {"cpuid": 100, "rdtsc": 100, "syscall": 100, "int": 100}}
        self.assertEqual(calculate_risk(report)["risk"]["threat_points"], 0)
        chrome = profile("installer")
        before = calculate_risk(chrome)["risk"]
        add_apis(chrome, *[f"OrdinaryFunction{i}" for i in range(1000)])
        chrome["imports"]["function_count"] += 1000
        self.assertEqual(calculate_risk(chrome)["risk"], before)

    def test_injection_requires_process_access_and_full_chain(self):
        report = ordinary("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
        self.assertEqual(calculate_risk(report)["risk"]["threat_points"], 0)
        add_apis(report, "OpenProcess")
        result = calculate_risk(report)
        self.assertGreaterEqual(result["risk"]["threat_points"], 6)

    def test_strong_chains_override_signed_installer_context(self):
        report = profile("installer")
        add_apis(report, "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CryptUnprotectData")
        report["strings"]["matches"]["browser_path"] = ["Google\\Chrome\\User Data"]
        report["strings"]["matches"]["browser_database"] = ["Login Data"]
        result = calculate_risk(report)
        self.assertIn(result["risk"]["verdict"], {"High Risk", "Dangerous"})
        for reason in result["reasons"]:
            if reason["id"] in {"injection_chain", "browser_credentials"}:
                self.assertEqual(reason["context_factor"], 1)
                self.assertGreater(reason["points"], 0)
        report["file"]["sections"][0].update(name="UPX1", entropy=7.9, writable=True)
        self.assertNotEqual(calculate_risk(report)["risk"]["verdict"], "Inconclusive")
        self.assertEqual(calculate_risk(report)["visibility"]["level"], "SEVERELY_LIMITED")

    def test_signature_is_not_a_blanket_discount_or_publisher_verification(self):
        report = ordinary("OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
        before = calculate_risk(report)["risk"]
        report["signature"] = {"signed": True, "integrity": "VALID", "known_ca": True,
                               "publishers": [{"subject": "CN=Familiar Vendor", "issuer": "CN=Famous CA"}]}
        after = calculate_risk(report)
        self.assertEqual(before, after["risk"])
        self.assertFalse(after["trust"]["publisher_verified"])

    def test_certificate_bytes_excluded_but_payload_after_certificate_is_kept(self):
        layout = overlay_layout(2000, 1000, 1100, 400)
        self.assertEqual(layout["certificate_bytes"], 400)
        self.assertEqual(layout["payload_bytes"], 600)
        self.assertEqual(layout["payload_ranges"], [{"offset": 1000, "size": 100}, {"offset": 1500, "size": 500}])
        certificate_only = profile("installer")
        self.assertEqual(certificate_only["file"]["overlay"]["payload_bytes"], 0)
        self.assertNotIn("opaque_appended_payload", [r["id"] for r in calculate_risk(certificate_only)["visibility"]["reasons"]])
        self.assertEqual(overlay_layout(2000, 1000, 1500, 1000)["certificate_bytes"], 0)

    def test_large_unverified_certificate_claim_is_a_visibility_gap(self):
        report = ordinary()
        report["file"]["overlay"].update(certificate_bytes=3500)
        report["signature"]["integrity"] = "UNKNOWN"
        result = calculate_risk(report)
        self.assertEqual(result["risk"]["threat_points"], 0)
        self.assertEqual(result["visibility"]["level"], "SEVERELY_LIMITED")

    def test_installer_role_does_not_suppress_unrelated_bundled_script_behavior(self):
        report = profile("installer")
        finding = {"id": "autorun_write", "family": "persistence", "strength": "moderate",
                   "reason": "Recovered script persistence", "base_points": 1.5, "contextual": True,
                   "evidence": {"source": "overlay::embedded.py"}}
        report["payload_inspection"] = {"status": "inspected", "archive": {"status": "inspected", "scripts": [{"status": "inspected", "findings": [finding]}]}}
        result = calculate_risk(report)
        recovered = next(reason for reason in result["reasons"] if reason["evidence"].get("source") == "overlay::embedded.py")
        self.assertEqual(recovered["context_factor"], 1)
        self.assertEqual(recovered["points"], 1.5)

    def test_complete_source_payload_does_not_keep_opaque_payload_penalty(self):
        report = ordinary()
        report["file"]["overlay"] = {"payload_bytes": 1000000, "payload_fraction": 0.9}
        report["payload_inspection"] = {"status": "inspected"}
        self.assertEqual(calculate_risk(report)["visibility"]["level"], "GOOD")
        report["payload_inspection"]["status"] = "partial"
        self.assertEqual(calculate_risk(report)["risk"]["verdict"], "Inconclusive")

    def test_scores_reconstruct_from_diagnostics_and_uncertainty_is_bounded(self):
        for name in ("installer", "packed_application", "opaque_container"):
            result = calculate_risk(profile(name))
            threat = round(min(10, sum(reason["points"] for reason in result["reasons"])), 1)
            self.assertEqual(threat, result["risk"]["threat_points"])
            self.assertEqual(max(threat, result["risk"]["uncertainty_floor"]), result["risk"]["points"])
            self.assertLessEqual(result["risk"]["uncertainty_floor"], 3.5)

    def test_same_behavior_is_not_counted_twice_across_layers(self):
        report = ordinary("OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
        before = calculate_risk(report)
        feature = before["behaviors"][0]
        report["payload_inspection"] = {"status": "inspected", "archive": {"status": "inspected", "scripts": [{"status": "inspected", "findings": [feature, copy.deepcopy(feature)]}]}}
        self.assertEqual(calculate_risk(report)["risk"]["threat_points"], before["risk"]["threat_points"])


if __name__ == "__main__":
    unittest.main()
