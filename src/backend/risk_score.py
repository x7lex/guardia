"""Independent heuristic score followed by an explicit hash reputation decision."""

from backend.evidence import supplementary_findings
from backend.features import detect_features, import_names, native_capabilities
from backend.reputation import applicable_reputation
from backend.signatures import signature_state

MODEL_VERSION = "5.0"
# Signature weights apply to ambiguous evidence, never to reputation overrides.
SIGNATURE_POLICY = {
    "unsigned": {"baseline": 4.0, "weak": 1.5, "moderate": 1.75, "strong": 1.5},
    "invalid": {"baseline": 5.0, "weak": 1.5, "moderate": 1.75, "strong": 1.5},
    "unknown": {"baseline": 3.0, "weak": 1.0, "moderate": 1.0, "strong": 1.0},
    "valid_unrecognized": {
        "baseline": 0.5,
        "weak": 0.75,
        "moderate": 1.0,
        "strong": 1.0,
    },
    "recognized_signed": {"baseline": 0.0, "weak": 0.2, "moderate": 0.6, "strong": 1.0},
    "trusted_signed": {"baseline": 0.0, "weak": 0.1, "moderate": 0.5, "strong": 1.0},
}
# Rule weights are centralized here so older saved findings use current policy.
RULE_WEIGHTS = {
    "injection_chain": (3.0, "strong", "injection"),
    "browser_credentials": (5.0, "strong", "credentials"),
    "script_browser_credentials": (5.0, "strong", "credentials"),
    "credential_exfiltration": (8.0, "strong", "credentials"),
    "autorun_write": (0.75, "weak", "persistence"),
    "startup_write": (0.75, "weak", "persistence"),
    "service_persistence": (2.0, "moderate", "persistence"),
    "scheduled_task": (2.0, "moderate", "persistence"),
    "download_launch": (0.5, "weak", "execution"),
    "suspicious_shell": (2.0, "moderate", "execution"),
    "script_download_execute": (4.0, "strong", "execution"),
    "anti_analysis_checks": (0.5, "weak", "anti_analysis"),
    "anti_vm": (0.25, "weak", "anti_analysis"),
    "encoded_script_execution": (1.25, "moderate", "concealment"),
    "concealed_script_execution": (1.25, "moderate", "concealment"),
    "obfuscated_runtime_resolution": (1.25, "moderate", "concealment"),
}


def get_risk_level(points):
    for ceiling, level in ((3, "Low Risk"), (5, "Suspicious"), (8, "High Risk")):
        if points < ceiling:
            return level
    return "Dangerous"


def import_combination(report):
    apis = import_names(report)
    facts = native_capabilities(report)
    categories = {
        "crypto_credentials": sorted(
            apis
            & {
                "cryptunprotectdata",
                "cryptprotectdata",
                "cryptdecrypt",
                "cryptencrypt",
                "cryptacquirecontexta",
                "cryptacquirecontextw",
                "bcryptencrypt",
                "bcryptdecrypt",
                "bcryptgenrandom",
                "ncryptunprotectsecret",
                "credreada",
                "credreadw",
                "credenumeratea",
                "credenumeratew",
            }
        ),
        "network": sorted(
            apis
            & {
                "connect",
                "wsaconnect",
                "send",
                "wsasend",
                "recv",
                "internetconnecta",
                "internetconnectw",
                "internetopenurla",
                "internetopenurlw",
                "httpsendrequesta",
                "httpsendrequestw",
                "winhttpconnect",
                "winhttpsendrequest",
                "winhttpwritedata",
                "winhttpreaddata",
                "internetreadfile",
                "urldownloadtofilea",
                "urldownloadtofilew",
            }
        ),
        "system_process": sorted(
            set(
                facts["process_access"]
                + facts["remote_write"]
                + facts["remote_execute"]
                + facts["process_execute"]
                + facts["registry_write"]
                + facts["service_create"]
            )
            | (
                apis
                & {
                    "adjusttokenprivileges",
                    "duplicatetokenex",
                    "readprocessmemory",
                    "ntreadvirtualmemory",
                    "createtoolhelp32snapshot",
                }
            )
        ),
    }
    present = {key: value for key, value in categories.items() if value}
    if len(present) < 2:
        return []
    # Three categories amplify the pair weight, independently of signature.
    return [
        {
            "id": "import_combination",
            "family": "import_combination",
            "strength": "weak",
            "reason": "Multiple import categories coexist; crypto/credentials with networking and process APIs deserves extra review",
            "base_points": 0.5 if len(present) == 2 else 1.0,
            "evidence": {
                "source": "outer_pe",
                "categories": present,
                "category_factor": len(present) - 1,
                "limitation": "Imports establish capabilities, not execution or data flow.",
            },
        }
    ]


def calculate_risk(
    report, user_elevation=False, sensitive_metadata=False, reputation=None
):
    state = signature_state(report.get("signature", {}))
    policy = SIGNATURE_POLICY[state]
    reasons = [
        {
            "id": "signature_baseline",
            "family": "signature",
            "strength": "baseline",
            "reason": f"Signature state: {state}; unsigned is a review signal, not proof of malware",
            "nominal_points": policy["baseline"],
            "signature_factor": 1.0,
            "category_factor": 1.0,
            "points": policy["baseline"],
            "evidence": report.get("signature", {}),
        }
    ]
    features = [f for f in detect_features(report) if f["id"] != "signature_integrity"]
    features += import_combination(report) + supplementary_findings(report)
    winners = {}
    for feature in features:
        base, strength, family = RULE_WEIGHTS.get(
            feature["id"],
            (
                feature.get("base_points", 0.0),
                feature.get("strength", "weak"),
                feature["family"],
            ),
        )
        # Injection is specific but dual-use. The unsigned baseline already
        # raises concern; injection alone must not imply confirmed malware.
        factor = (
            1.0 if feature["id"] == "injection_chain" else policy.get(strength, 1.0)
        )
        adjusted = round(base * factor, 3)
        reason = {
            **feature,
            "base_points": base,
            "family": family,
            "strength": strength,
            "nominal_points": base,
            "signature_factor": factor,
            "category_factor": 1.0,
            "points": 0.0,
            "scoring": "Informational or covered by the strongest finding in this family",
        }
        reasons.append(reason)
        if adjusted > winners.get(family, (0, None))[0]:
            winners[family] = (adjusted, reason)
    # Packing/entropy/RWX are one domain; overlapping import and behavior rules
    # are one domain. This prevents counting the same underlying clue twice.
    domains = set()
    for family, (_, reason) in winners.items():
        if reason.get("correlation_eligible", True):
            domains.add(
                "structure"
                if family in {"structure", "concealment"}
                else "behavior"
                if family not in {"cpu", "yara"}
                else family
            )
    step = 0.25 if state in {"unsigned", "invalid"} else 0.1
    cross_factor = 1 + step * min(2, max(0, len(domains) - 1))
    behavior_families = {
        f
        for f in winners
        if f
        in {"injection", "credentials", "execution", "persistence", "anti_analysis"}
    }
    behavior_factor = 1.25 if len(behavior_families) >= 2 else 1.0
    for family, (adjusted, reason) in winners.items():
        factor = cross_factor * (behavior_factor if family in behavior_families else 1)
        reason.update(
            points=round(adjusted * factor, 3),
            category_factor=factor,
            scoring="Strongest family finding × signature multiplier × cross-domain/behavior correlation",
        )
    total = round(sum(r["points"] for r in reasons), 3)
    heuristic = round(min(10.0, max(0.0, total)), 1)
    reputation_status = applicable_reputation(
        reputation, report.get("file", {}).get("sha256")
    )
    points, source, override = heuristic, "heuristics", None
    reputation_adjustment = 0.0
    baseline_credit = weak_credit = 0.0
    if reputation_status == "known_malicious":
        points, source = 10.0, "reputation_override"
        override = {
            "type": "known_malicious_sha256",
            "provider": reputation["provider"],
            "reason": reputation["reason"],
            "sha256": reputation["sha256"],
        }
    elif reputation_status == "reputable":
        # Reputation can corroborate benign unsigned software, but it cannot
        # discount invalid signing, moderate/strong behavior or a malicious match.
        baseline_credit = 2.0 if state == "unsigned" else 0.0
        weak_credit = round(
            sum(r["points"] for r in reasons if r["strength"] == "weak") * 0.5, 3
        )
        reputation_adjustment = round(baseline_credit + weak_credit, 3)
        points = round(min(10.0, max(0.0, total - reputation_adjustment)), 1)
        source = "heuristics_with_positive_reputation"
    return {
        "model_version": MODEL_VERSION,
        "file_name": report.get("file", {}).get("file_name"),
        "sha256": report.get("file", {}).get("sha256"),
        "signature_state": state,
        "heuristic": {
            "points": heuristic,
            "level": get_risk_level(heuristic),
            "uncapped_score": total,
        },
        "risk": {
            "points": points,
            "score": f"{points:.1f}/10.0",
            "level": get_risk_level(points),
            "verdict": get_risk_level(points),
            "classification": "known_malicious" if override else "heuristic_risk",
            "source": source,
            "score_meaning": "Static risk, not probability; known-malicious reputation is a separate override",
        },
        "decision": {
            "source": source,
            "override": override,
            "positive_reputation_discount": reputation_adjustment,
            "unsigned_baseline_credit": baseline_credit,
            "weak_evidence_credit": weak_credit,
        },
        "reasons": reasons,
        "diagnostics": {
            "uncapped_score": total,
            "signature_policy": SIGNATURE_POLICY,
            "active_domains": sorted(domains),
            "cross_domain_factor": cross_factor,
            "behavior_factor": behavior_factor,
            "active_behavior_families": sorted(behavior_families),
            "heuristic_formula": "round(clamp(sum(reasons.points), 0, 10), 1)",
            "final_score_formula": "10 for exact known-malicious reputation; otherwise round(clamp(uncapped heuristic - positive reputation discount, 0, 10), 1)",
            "limitations": [
                "Static capabilities do not prove execution; packed and hidden code can be missed.",
                "Issuer recognition is not OS certificate-chain validation; injection also occurs in cheats and debuggers.",
                "High heuristic risk is not a confirmed malware diagnosis; absence of reputation records is not safety.",
            ],
            "unscored_context": {
                "user_elevation": user_elevation,
                "sensitive_metadata": sensitive_metadata,
            },
        },
    }
