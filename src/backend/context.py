"""Executable role and signature context; no identity allowlists or score deductions."""

import re

from backend.features import import_names, is_packed, native_capabilities, packing_facts


def assess_trust(report):
    signature = report.get("signature", {})
    publishers = signature.get("publishers", [])
    names = []
    for publisher in publishers:
        subject = publisher.get("subject", "")
        match = re.search(r"(?:^|,\s*)CN=([^,]+)", subject)
        names.append(match.group(1) if match else subject)
    integrity = signature.get("integrity", "UNKNOWN")
    chain = signature.get("chain_trust", "NOT_EVALUATED")
    identity = signature.get("publisher_identity", "NOT_TRUST_VALIDATED")
    revocation = signature.get("revocation", "NOT_CHECKED")
    verified = integrity == "VALID" and chain == "TRUSTED" and identity == "VERIFIED"
    return {
        "signed": bool(signature.get("signed")),
        "signature_integrity": integrity,
        "chain_trust": chain,
        "publisher": names[0] if names else None,
        "publishers": publishers,
        "publisher_identity": identity,
        "publisher_verified": verified,
        "revocation": revocation,
        "fully_verified": verified and revocation == "GOOD",
        "policy": "Signature integrity is separate from chain trust, identity and revocation. Issuer names and known_ca never establish publisher trust. No flat risk deduction.",
    }


def assess_context(report, trust):
    facts = native_capabilities(report)
    apis = import_names(report)
    packing = packing_facts(report)
    file = report.get("file", {})
    hits = report.get("strings", {}).get("matches", {})
    version = file.get("version_info", {})
    # Metadata is claimed role evidence, never identity verification. No input filename check.
    role_metadata = {
        k: v
        for k, v in version.items()
        if k in {"FileDescription", "ProductName", "InternalName"}
        and re.search(r"(?i)install|updat|setup", str(v))
    }
    terms = hits.get("installer_terms", [])
    # Old reports lack the dedicated category. Use URL path semantics, not a domain allowlist.
    url_role_hints = [
        s for s in hits.get("url", []) if re.search(r"(?i)/[^?#]*(?:install|update)", s)
    ]
    lifecycle = (
        facts["service_create"] and facts["service_config"] and apis & {"deleteservice"}
    )
    clues = []
    if role_metadata:
        clues.append({"id": "installer_metadata", "evidence": role_metadata})
    if terms or url_role_hints:
        clues.append(
            {"id": "installation_vocabulary", "evidence": (terms + url_role_hints)[:10]}
        )
    if lifecycle:
        clues.append(
            {
                "id": "service_lifecycle",
                "evidence": facts["service_create"]
                + facts["service_config"]
                + ["deleteservice"],
            }
        )
    if facts["file_write"] and facts["process_execute"] and facts["registry_write"]:
        clues.append(
            {
                "id": "installation_capabilities",
                "evidence": {
                    key: facts[key]
                    for key in ("file_write", "process_execute", "registry_write")
                },
            }
        )
    installer = len(clues) >= 3 and bool(role_metadata or terms or url_role_hints)
    if is_packed(packing):
        role, confidence = (
            "packed_application",
            0.9 if packing["packer_sections"] else 0.7,
        )
    elif installer:
        role, confidence = "installer_updater", 0.85 if role_metadata else 0.65
        if trust["signature_integrity"] == "VALID":
            confidence = min(0.95, confidence + 0.05)
            clues.append(
                {
                    "id": "integrity_valid",
                    "evidence": "Valid signature corroborates metadata integrity, not publisher trust",
                }
            )
    elif file.get("is_dll"):
        role, confidence = "library", 0.9
    elif file.get("overlay", {}).get("payload_fraction", 0) >= 0.3 and (
        report.get("payload_inspection") or {}
    ).get("container_candidates"):
        role, confidence = "container_application", 0.8
    else:
        role, confidence = "unknown", 0.0
    return {
        "likely_role": role,
        "confidence": round(confidence, 2),
        "evidence": clues,
        "limitations": [
            "Role is inferred from co-occurring static clues. A claimed installer can still be malicious."
        ],
        "installer_adjustment_eligible": role == "installer_updater"
        and confidence >= 0.6,
    }
