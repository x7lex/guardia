"""Auditable triage with independent evidence, visibility, trust and role models."""
from backend.features import detect_features
from backend.context import assess_context, assess_trust
from backend.visibility import assess_visibility

MODEL_VERSION = "3.0"
# These apply only to archived script findings which predate base_points.
LEGACY_SCRIPT_WEIGHTS = {"encoded_script_execution": 1.0, "concealed_script_execution": 1.0,
                         "obfuscated_runtime_resolution": 0.0, "script_browser_credentials": 6.0,
                         "credential_exfiltration": 4.0}
FAMILY_CAPS = {"injection": 6.0, "credentials": 6.0, "exfiltration": 4.0,
               "execution": 4.0, "persistence": 2.5, "anti_analysis": 1.0, "integrity": 3.0}


def get_risk_level(points):
    for ceiling, level in ((4, "Low Risk"), (6, "Suspicious"), (8, "High Risk")):
        if points < ceiling:
            return level
    return "Dangerous"


def calculate_risk(report, user_elevation=False, sensitive_metadata=False):
    trust = assess_trust(report)
    context = assess_context(report, trust)
    visibility = assess_visibility(report)
    features = detect_features(report)
    reasons = []
    for feature in features:
        base = feature.get("base_points", LEGACY_SCRIPT_WEIGHTS.get(feature["id"], 0.0))
        # The old packing family is now exclusively visibility, except explicit sinks.
        factor = 1.0
        if (feature.get("contextual") and context["installer_adjustment_eligible"]
                and feature.get("evidence", {}).get("source") == "outer_pe"):
            factor = 0.25 if trust["signature_integrity"] == "VALID" else 0.5
        reasons.append({**feature, "nominal_points": base, "context_factor": factor,
                        "adjusted_points": round(base * factor, 3), "points": 0.0,
                        "context_reason": "Expected installer capability; target linkage is unproven" if factor < 1 else "No role adjustment",
                        "scoring": "Informational; no threat points"})
    # Per-family max deduplicates source layers and equivalent native/script chains.
    # Visibility is assessed separately and never collapses into this maximum.
    family_scores = {}
    for family, cap in FAMILY_CAPS.items():
        candidates = [reason for reason in reasons if reason["family"] == family and reason["adjusted_points"] > 0]
        if not candidates:
            continue
        winner = max(candidates, key=lambda r: r["adjusted_points"])
        winner["points"] = min(cap, winner["adjusted_points"])
        winner["scoring"] = "Strongest behavior in family, subject to family cap"
        for other in candidates:
            if other is not winner:
                other["scoring"] = "Covered by stronger/equivalent behavior in the same family"
        family_scores[family] = winner["points"]
    uncapped = sum(family_scores.values())
    threat = round(min(10.0, uncapped), 1)
    # A bounded triage floor prompts review; uncertainty can never establish High Risk.
    floor = round(min(3.5, 4.0 * (1.0 - visibility["score"])), 1) if visibility["requires_review"] else 0.0
    points = max(threat, floor)
    level = get_risk_level(points)
    verdict = "Inconclusive" if visibility["requires_review"] and threat < 6 else level
    limitations = list(dict.fromkeys([r["reason"] for r in visibility["reasons"]] +
        ["Static capabilities are not observed behavior; absence of findings is not proof of safety.",
         "Co-occurring imports/strings do not establish argument linkage, call order or reachability."]))
    return {"model_version": MODEL_VERSION, "file_name": report.get("file", {}).get("file_name"),
            "sha256": report.get("file", {}).get("sha256"),
            "risk": {"points": points, "score": f"{points:.1f}/10.0", "level": level, "verdict": verdict,
                     "confidence": visibility["score"], "coverage_limited": visibility["requires_review"],
                     "threat_points": threat, "uncertainty_floor": floor,
                     "uncertainty_contribution": round(points - threat, 1),
                     "score_meaning": "Triage priority, not malware probability; max(threat evidence, bounded visibility floor)",
                     "confidence_meaning": "Static visibility index; not calibrated confidence in the verdict"},
            "visibility": visibility, "trust": trust, "context": context,
            "behaviors": [r for r in reasons if r["family"] in FAMILY_CAPS], "reasons": reasons,
            "diagnostics": {"uncapped_threat_score": uncapped, "family_scores": family_scores,
                            "family_caps": FAMILY_CAPS,
                            "family_policy": "Strongest correlated behavior per family; sum families and cap threat at 10. Visibility does not add threat points.",
                            "final_score_formula": "max(round(min(10, sum(family_scores)), 1), round(min(3.5, 4*(1-visibility)), 1) if visibility<0.75 else 0)",
                            "verdict_policy": "Visibility below 0.75 with threat below 6 is Inconclusive. Strong threat evidence overrides the uncertainty verdict, never its coverage disclosure.",
                            "signature_policy": trust["policy"],
                            "unscored_context": {"user_elevation": user_elevation, "sensitive_metadata": sensitive_metadata},
                            "limitations": limitations,
                            "assessment": "limited_visibility" if visibility["requires_review"] else "static_triage"}}
