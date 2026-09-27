"""Deterministic signature baseline plus amplified capability combinations."""
from backend.features import detect_features, import_names, native_capabilities
from backend.signatures import signature_state

MODEL_VERSION = "4.0"
# baseline, weak finding multiplier, strong finding multiplier
SIGNATURE_POLICY = {
    "unsigned": (4.0, 1.5, 1.5),
    "invalid": (5.0, 1.5, 1.5),
    "unknown": (3.0, 1.0, 1.0),
    "valid_unrecognized": (0.5, 0.8, 1.0),
    "trusted_signed": (0.0, 0.1, 1.0),
}
LEGACY_SCRIPT_WEIGHTS = {"encoded_script_execution": 1.0, "concealed_script_execution": 1.0,
                         "script_browser_credentials": 6.0, "credential_exfiltration": 4.0}


def get_risk_level(points):
    for ceiling, level in ((4, "Low Risk"), (6, "Suspicious"), (8, "High Risk")):
        if points < ceiling:
            return level
    return "Dangerous"


def import_combination(report):
    apis = import_names(report)
    facts = native_capabilities(report)
    categories = {
        "crypto_credentials": sorted(apis & {
            "cryptunprotectdata", "cryptprotectdata", "cryptdecrypt", "cryptencrypt",
            "cryptacquirecontexta", "cryptacquirecontextw", "bcryptencrypt", "bcryptdecrypt",
            "bcryptgenrandom", "ncryptunprotectsecret", "credreada", "credreadw",
            "credenumeratea", "credenumeratew"}),
        "network": sorted(apis & {"connect", "wsaconnect", "send", "wsasend", "recv",
            "internetconnecta", "internetconnectw", "internetopenurla", "internetopenurlw",
            "httpsendrequesta", "httpsendrequestw", "winhttpconnect", "winhttpsendrequest",
            "winhttpwritedata", "winhttpreaddata", "internetreadfile",
            "urldownloadtofilea", "urldownloadtofilew"}),
        "system_process": sorted(set(facts["process_access"] + facts["remote_write"] +
            facts["remote_execute"] + facts["process_execute"] + facts["registry_write"] +
            facts["service_create"]) | (apis & {"adjusttokenprivileges", "duplicatetokenex",
            "readprocessmemory", "ntreadvirtualmemory", "createtoolhelp32snapshot"})),
    }
    present = {key: value for key, value in categories.items() if value}
    if len(present) < 2:
        return []
    # Three categories amplify the pair weight, independently of signature.
    return [{"id": "import_combination", "family": "import_combination", "strength": "moderate",
             "reason": "Multiple import categories coexist; crypto/credentials with networking and process APIs deserves extra review",
             "base_points": 1.5 if len(present) == 2 else 3.0,
             "evidence": {"source": "outer_pe", "categories": present,
                          "category_factor": len(present) - 1,
                          "limitation": "Imports establish capabilities, not execution or data flow."}}]


def calculate_risk(report, user_elevation=False, sensitive_metadata=False):
    state = signature_state(report.get("signature", {}))
    baseline, weak_factor, strong_factor = SIGNATURE_POLICY[state]
    reasons = [{"id": "signature_baseline", "family": "signature", "strength": "baseline",
                "reason": f"Signature state: {state}", "nominal_points": baseline,
                "signature_factor": 1.0, "category_factor": 1.0, "points": baseline,
                "evidence": report.get("signature", {})}]
    features = [f for f in detect_features(report) if f["id"] != "signature_integrity"]
    features += import_combination(report)
    # Keep one strongest finding per family, including across recovered source layers.
    winners = {}
    for feature in features:
        base = feature.get("base_points", LEGACY_SCRIPT_WEIGHTS.get(feature["id"], 0.0))
        strong = feature.get("strength") == "strong"
        factor = strong_factor if strong else weak_factor
        adjusted = round(base * factor, 3)
        reason = {**feature, "nominal_points": base, "signature_factor": factor,
                  "category_factor": 1.0, "points": 0.0,
                  "scoring": "Informational or covered by a stronger finding in this family"}
        reasons.append(reason)
        family = feature["family"]
        if adjusted > winners.get(family, (0, None))[0]:
            winners[family] = (adjusted, reason)
    # Independent behavioral families amplify each other; packing and CPU do not.
    families = sorted(winners)
    amplification = 1.0 + 0.25 * min(2, max(0, len(families) - 1))
    for adjusted, reason in winners.values():
        reason.update(points=round(adjusted * amplification, 3), category_factor=amplification,
                      scoring="Strongest finding in family × signature factor × multiple-family factor")
    counts = report.get("disassembly", {}).get("mnemonic_counts", {})
    cpu_groups = {"discovery_timing": {"cpuid", "rdtsc", "rdtscp"},
                  "system_transition": {"syscall", "sysenter", "int"},
                  "privileged": {"in", "out", "rdmsr", "wrmsr", "cli", "sti", "hlt"}}
    observed = {group: {k: counts[k] for k in sorted(names) if counts.get(k, 0) > 0}
                for group, names in cpu_groups.items()}
    observed = {group: hits for group, hits in observed.items() if hits}
    cpu_base = min(0.75, 0.25 * len(observed))
    reasons.append({"id": "cpu_instructions", "family": "cpu", "strength": "weak",
                    "reason": "0.25 per instruction group, capped at 0.75; repetition and ordinary instructions add nothing",
                    "nominal_points": cpu_base, "signature_factor": min(1.0, weak_factor),
                    "category_factor": 1.0, "points": round(cpu_base * min(1.0, weak_factor), 3),
                    "evidence": {"groups": observed, "scope": report.get("disassembly", {}).get("scope")}})
    total = round(sum(r["points"] for r in reasons), 3)
    points = round(min(10.0, max(0.0, total)), 1)
    level = get_risk_level(points)
    return {"model_version": MODEL_VERSION, "file_name": report.get("file", {}).get("file_name"),
            "sha256": report.get("file", {}).get("sha256"),
            "risk": {"points": points, "score": f"{points:.1f}/10.0", "level": level, "verdict": level,
                     "score_meaning": "Conservative static risk score, not malware probability"},
            "signature_state": state, "reasons": reasons,
            "diagnostics": {"uncapped_score": total, "signature_policy": {key: dict(zip(("baseline", "weak_multiplier", "strong_multiplier"), values))
                                                 for key, values in SIGNATURE_POLICY.items()},
                            "active_families": families, "category_factor": amplification,
                            "final_score_formula": "round(min(10, max(0, sum(reasons.points))), 1)",
                            "limitations": ["Static capabilities do not prove execution; hidden code can be missed.",
                                "Recognized issuer is a scoring policy, not OS chain or revocation validation.",
                                "Packing and extraction limitations are informational, not scored."],
                            "unscored_context": {"user_elevation": user_elevation, "sensitive_metadata": sensitive_metadata}}}
