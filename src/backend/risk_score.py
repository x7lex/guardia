"""Explainable family-capped scoring over static features."""

from backend.features import detect_features

MODEL_VERSION = "2.2"
# Each family contributes its strongest finding only. These are triage weights,
# not calibrated probabilities. Weak capabilities together have a global cap.
WEIGHTS = {
    "injection_chain": 4.0, "browser_credentials": 3.0,
    "autorun_write": 2.0, "service_creation": 0.5, "startup_write": 2.0,
    "scheduled_task": 2.0, "suspicious_shell": 2.5,
    "script_download_execute": 4.0, "download_launch": 0.5,
    "anti_debug": 0.5, "anti_vm": 0.5, "rwx_sections": 0.5,
    "packed_layout": 2.0, "dynamic_resolution": 0.0,
    "invalid_section_range": 1.0, "signature_integrity": 3.0,
    "uninspected_payload": 0.0,
    "encoded_script_execution": 4.0, "script_browser_credentials": 4.0,
    "credential_exfiltration": 4.0,
    "concealed_script_execution": 4.0,
    "obfuscated_runtime_resolution": 1.5,
}
SUPPORTING = {"packing", "anti_analysis"}


def get_risk_level(points):
    for ceiling, level in ((2, "No indicators detected"), (4, "Low Risk"), (6, "Suspicious"), (8, "High Risk")):
        if points < ceiling:
            return level
    return "Dangerous"


def calculate_risk(report, user_elevation=False, sensitive_metadata=False):
    features = detect_features(report)
    winners = {}
    for feature in features:
        family = feature["family"]
        if family not in winners or WEIGHTS[feature["id"]] > WEIGHTS[winners[family]["id"]]:
            winners[family] = feature
    reasons = []
    support_remaining = 2.5
    for feature in features:
        nominal = WEIGHTS[feature["id"]]
        contribution = nominal if winners[feature["family"]] is feature else 0.0
        explanation = "Strongest finding in family" if contribution else "Informational or covered by stronger finding in family"
        if feature["family"] in SUPPORTING:
            capped = min(contribution, support_remaining)
            if capped < contribution:
                explanation += "; reduced by supporting-evidence cap"
            contribution = capped
            support_remaining -= contribution
        reasons.append({**feature, "nominal_points": nominal, "points": contribution, "scoring": explanation})
    raw = sum(item["points"] for item in reasons)
    points = round(min(raw, 10.0), 1)
    signature = report.get("signature", {})
    limitations = list(report.get("coverage", {}).get("limitations", []))
    limited_visibility = bool(limitations) or any(f["id"] in {"packed_layout", "uninspected_payload", "invalid_section_range", "obfuscated_runtime_resolution"} for f in features)
    if any(f["id"] == "uninspected_payload" for f in features):
        limitations.append("Substantial appended payload is only partially covered; inspect payload_inspection for recovered source and remaining limits.")
    limitations.append("Static capabilities are not observed behavior; absence of findings is not proof of safety.")
    if any(f["id"] == "packed_layout" for f in features):
        limitations.append("Likely packed native code remains opaque; no native unpacking or target execution was performed.")
    return {
        "model_version": MODEL_VERSION,
        "file_name": report.get("file", {}).get("file_name"),
        "sha256": report.get("file", {}).get("sha256"),
        "risk": {"points": points, "score": f"{points:.1f}/10.0",
                 "level": "Use at your own risk" if limited_visibility and points < 4 else get_risk_level(points),
                 "coverage_limited": limited_visibility},
        "reasons": reasons,
        "diagnostics": {"uncapped_score": raw, "family_policy": "Maximum per family; packing and anti-analysis together capped at 2.5",
                        "signature_context": signature,
                        "signature_policy": "Valid integrity is legitimacy context; no deduction masks behavioral evidence. Chain trust is not inferred from issuer names.",
                        "unscored_context": {"user_elevation": user_elevation, "sensitive_metadata": sensitive_metadata},
                        "limitations": limitations,
                        "assessment": "limited_visibility" if limited_visibility else "static_triage"},
    }
