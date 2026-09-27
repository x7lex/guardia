"""Source-grounded structural and instruction evidence; independent of scoring."""

from backend.features import packing_facts


def supplementary_findings(report):
    findings = []

    def add(identifier, family, strength, points, reason, evidence, correlation=True):
        findings.append(
            {
                "id": identifier,
                "family": family,
                "strength": strength,
                "base_points": points,
                "reason": reason,
                "evidence": evidence,
                "correlation_eligible": correlation,
            }
        )

    packing = packing_facts(report)
    if packing["packer_sections"]:
        add(
            "packer_layout",
            "concealment",
            "weak",
            1.0,
            "Recognized packed section layout can conceal code; also common in protected software",
            packing,
        )
    elif packing["high_entropy_code"]:
        add(
            "high_entropy_code",
            "concealment",
            "weak",
            0.25,
            "High entropy executable code; encryption/compression alone does not prove malware",
            packing,
        )
    if packing["rwx"]:
        add(
            "writable_executable_sections",
            "structure",
            "weak",
            0.35,
            "Writable executable sections can support unpacking or runtime code generation",
            {"sections": packing["rwx"]},
        )
    overlay = report.get("file", {}).get("overlay", {})
    inspection = report.get("payload_inspection") or {}
    if (
        overlay.get("payload_fraction", 0) >= 0.5
        and inspection.get("status") != "inspected"
    ):
        add(
            "opaque_appended_payload",
            "concealment",
            "weak",
            0.75,
            "Most file bytes are an incompletely inspected appended payload",
            {
                "payload_fraction": overlay["payload_fraction"],
                "inspection_status": inspection.get("status", "not_inspected"),
            },
        )
    anomalies = report.get("file", {}).get("header_anomalies", [])
    bad_sections = [
        s.get("name")
        for s in report.get("file", {}).get("sections", [])
        if s.get("raw_out_of_bounds")
    ]
    if anomalies or bad_sections:
        add(
            "malformed_layout",
            "structure",
            "moderate",
            1.0,
            "PE header/section ranges are inconsistent",
            {"header_anomalies": anomalies, "out_of_bounds_sections": bad_sections},
        )
    counts = report.get("disassembly", {}).get("mnemonic_counts", {})
    groups = {
        "discovery_timing": {"cpuid", "rdtsc", "rdtscp"},
        "system_transition": {"syscall", "sysenter", "int"},
        "privileged": {"in", "out", "rdmsr", "wrmsr", "cli", "sti", "hlt"},
    }
    hits = {
        group: {k: counts[k] for k in sorted(names) if counts.get(k, 0) > 0}
        for group, names in groups.items()
    }
    hits = {group: value for group, value in hits.items() if value}
    base = sum(0.25 if group == "privileged" else 0.1 for group in hits)
    add(
        "cpu_instructions",
        "cpu",
        "weak",
        min(0.5, base),
        "CPU groups contribute at most 0.5; counts, ordinary instructions and int3 padding add nothing",
        {"groups": hits, "scope": report.get("disassembly", {}).get("scope")},
        len(hits) >= 2 or "privileged" in hits,
    )
    yara = report.get("yara", {})
    if yara.get("status") == "complete":
        for match in yara.get("matches", []):
            meta = match.get("meta", {})
            strong = (
                meta.get("malware") is True
                and meta.get("confidence") == "high"
                and bool(yara.get("rules_sha256"))
            )
            add(
                "yara_match",
                "yara",
                "strong" if strong else "weak",
                8.0 if strong else 0.5,
                "High-specificity malware rule matched"
                if strong
                else "Generic YARA rule matched; not a confirmed malware signature",
                {"match": match, "rules_sha256": yara.get("rules_sha256")},
                strong,
            )
    return findings
