"""Conservative visibility ceilings, kept separate from malicious evidence.

A score is a heuristic static visibility index, not a measured analyzed byte fraction
or a probability. Correlated limitations constrain one ceiling rather than adding
independent penalties. FULL is intentionally unavailable to this bounded analyzer.
"""
from backend.features import packing_facts, is_packed, import_names


def assess_visibility(report):
    reasons = []
    def limit(identifier, ceiling, reason, evidence):
        reasons.append({"id": identifier, "ceiling": ceiling, "reason": reason, "evidence": evidence})
    packing = packing_facts(report)
    if is_packed(packing):
        limit("packed_native_code", 0.2 if packing["packer_sections"] else 0.35,
              "Packed native code has not been unpacked; visible imports describe its loader", packing)
    elif packing["high_entropy_code"]:
        limit("high_entropy_executable", 0.65, "High-entropy executable content may conceal code; no malware inference is made", packing)
    if not is_packed(packing) and not import_names(report):
        limit("missing_import_surface", 0.6, "No named import capabilities are available", {})
    if any(s.get("raw_out_of_bounds") for s in report.get("file", {}).get("sections", [])):
        limit("invalid_section_ranges", 0.35, "Invalid section bounds prevent reliable code inspection", {})
    file = report.get("file", {})
    overlay = file.get("overlay", {})
    inspection = report.get("payload_inspection") or {}
    certificate_fraction = overlay.get("certificate_bytes", 0) / max(file.get("file_size", 0), 1)
    if certificate_fraction >= 0.1 and report.get("signature", {}).get("integrity") != "VALID":
        limit("unverified_certificate_content", 0.2 if certificate_fraction >= 0.5 else 0.5,
              "A large claimed certificate table could not be validated; its contents are not established certificate data",
              {"certificate_bytes": overlay.get("certificate_bytes"), "fraction": certificate_fraction})
    if overlay.get("payload_bytes", 0) >= 65536 and inspection.get("status") != "inspected":
        fraction = overlay.get("payload_fraction", 0)
        ceiling = 0.2 if fraction >= 0.5 else 0.5 if fraction >= 0.1 else 0.75
        limit("opaque_appended_payload", ceiling, "Non-certificate appended content is only partially understood",
              {"payload_bytes": overlay.get("payload_bytes"), "payload_fraction": fraction,
               "certificate_bytes": overlay.get("certificate_bytes", 0), "inspection_status": inspection.get("status", "not_inspected"),
               "entropy": inspection.get("entropy"), "containers": inspection.get("container_candidates", [])})

    def walk_script(script):
        unresolved = script.get("unresolved_dynamic_imports", [])
        if unresolved or any(f.get("id") == "obfuscated_runtime_resolution" for f in script.get("findings", [])):
            limit("unresolved_script_names", 0.4, "Encoded runtime resolution leaves capabilities unknown",
                  {"source": script.get("source"), "lines": unresolved})
        if script.get("status") != "inspected":
            limit("partial_script", 0.55, "Script decoding or parsing is incomplete",
                  {"source": script.get("source"), "limitations": script.get("limitations", [])})
        for child in script.get("decoded_layers", []):
            walk_script(child)

    def walk_archive(archive):
        for script in archive.get("scripts", []):
            walk_script(script)
        counts = archive.get("member_status_counts", {})
        if archive.get("status") != "inspected":
            limit("partial_archive", 0.6, "Some archive members, native code, bytecode or nested layers remain opaque",
                  {"source": archive.get("source"), "member_status_counts": counts,
                   "limitations": archive.get("limitations", [])})
        for child in archive.get("nested_archives", []):
            walk_archive(child)

    def walk_inspection(item):
        if item.get("archive"):
            walk_archive(item["archive"])
        for region in item.get("regions", []):
            walk_inspection(region)
    walk_inspection(inspection)
    resources = report.get("resources")
    if resources:
        opaque = resources.get("opaque_bytes", 0)
        if opaque:
            fraction = opaque / max(file.get("file_size", 0), 1)
            limit("opaque_resources", 0.55 if fraction >= 0.1 else 0.7,
                  "Executable/archive resources were identified but their contents remain incompletely analyzed",
                  {"opaque_bytes": opaque, "fraction": round(fraction, 4), "limitations": resources.get("limitations", [])})
        if resources.get("truncated"):
            limit("resource_inventory_truncated", 0.6, "Resource inspection reached its bounds", {})
        for item in resources.get("inspections", []):
            walk_inspection(item)
    elif any(s.get("name") == ".rsrc" and s.get("raw_size", 0) >= 65536 for s in file.get("sections", [])):
        limit("legacy_resource_inventory_missing", 0.8, "Saved report has resource bytes but no resource inventory; rescan for embedded payloads", {})
    if report.get("strings", {}).get("truncated"):
        limit("string_scan_truncated", 0.6, "Only a prefix of the file was searched for string evidence", {})
    if inspection.get("truncated"):
        limit("payload_scan_truncated", 0.5, "Payload inspection reached its byte budget", {})
    for limitation in report.get("coverage", {}).get("limitations", []):
        # Signature confidence belongs in trust, not a code-visibility penalty.
        if "authenticode" not in limitation.lower():
            limit("reported_extraction_limit", 0.65, limitation, {})
    score = round(min([0.9] + [reason["ceiling"] for reason in reasons]), 2)
    level = "GOOD" if score >= 0.75 else "PARTIAL" if score >= 0.4 else "SEVERELY_LIMITED"
    return {"level": level, "score": score, "reasons": reasons, "requires_review": score < 0.75,
            "policy": "Minimum visibility ceiling across limitations; correlated indicators are not added. Baseline 0.90 reflects bounded static analysis, not complete behavior recovery.",
            "score_meaning": "Heuristic visibility index, not percent of code analyzed or probability of correctness"}
