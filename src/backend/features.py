"""Native capability facts and shared behavior correlations; no sample-specific rules."""

import re

from backend.behaviors import correlate_capabilities
from backend.payloads import script_findings

STRING_PATTERNS = {
    "browser_database": r"(?i)(?:login data|logins\.json|key[34]\.db|cookies|local state)",
    "browser_path": r"(?i)(?:google[\\/]chrome[\\/]user data|mozilla[\\/]firefox[\\/]profiles|microsoft[\\/]edge[\\/]user data)",
    "autorun": r"(?i)software[\\/]microsoft[\\/]windows[\\/]currentversion[\\/](?:runonce|run)(?:[\\/\s\x00]|$)",
    "startup": r"(?i)(?:start menu[\\/]programs[\\/]startup)",
    "scheduled_task": r"(?i)\bschtasks(?:\.exe)?\b[^\r\n]{0,400}/create\b[^\r\n]{0,400}/tr\b",
    "suspicious_shell": r"(?i)(?:powershell(?:\.exe)?[^\r\n]{0,300}(?:-(?:enc(?:odedcommand)?|windowstyle\s+hidden)\b|downloadstring|invoke-expression)|cmd(?:\.exe)?\s+/c[^\r\n]{0,300}(?:certutil[^\r\n]*-urlcache|bitsadmin[^\r\n]*/transfer))",
    "download_execute": r"(?i)(?:downloadstring\s*\([^\r\n]{0,300}\)[^\r\n]{0,80}\|\s*iex\b|iex\s*\([^\r\n]{0,300}downloadstring)",
    "vm_artifact": r"(?i)(?:vboxservice|vboxguest|vmtoolsd|vmwaretray|\\vboxguest)",
    "installer_terms": r"(?i)(?:uninstall(?:string)?|\bupdater?\b|\binstall(?:er|ation)?\b|program files|currentversion[\\/]uninstall)",
    "suspicious_executable_path": r"(?i)(?:%temp%|%appdata%|[\\/]appdata[\\/]|[\\/]temp[\\/])[^\r\n\x00]{0,200}\.(?:exe|dll|ps1|vbs)\b",
    "url": r"(?i)\bhttps?://[^\s\"'<>]{4,250}",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domain": r"(?i)\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top)\b",
}


def import_names(report):
    return {
        name.lower()
        for lib in report.get("imports", {}).get("libraries", [])
        for name in lib.get("functions", [])
        if name
    }


def native_capabilities(report):
    apis = import_names(report)
    hits = report.get("strings", {}).get("matches", {})

    def matches(*names):
        return sorted(apis.intersection(names))

    debug = matches("isdebuggerpresent", "checkremotedebuggerpresent")
    allocator = matches(
        "virtualallocex", "ntallocatevirtualmemory", "zwallocatevirtualmemory"
    )
    remote = matches(
        "createremotethread",
        "createremotethreadex",
        "ntcreatethreadex",
        "queueuserapc",
        "ntqueueapcthread",
    )
    context = matches("setthreadcontext", "ntsetcontextthread")
    resume = matches("resumethread", "ntresumethread")
    write = matches(
        "writefile",
        "writefileex",
        "ntwritefile",
        "fwrite",
        "copyfilea",
        "copyfilew",
        "urldownloadtofilea",
        "urldownloadtofilew",
    )
    return {
        "process_access": matches("openprocess", "ntopenprocess", "zwopenprocess"),
        "remote_allocate": allocator,
        "remote_write": matches(
            "writeprocessmemory", "ntwritevirtualmemory", "zwwritevirtualmemory"
        ),
        "remote_execute": remote or (context + resume if context and resume else []),
        "browser_profile": hits.get("browser_path", []),
        "credential_storage": hits.get("browser_database", []),
        "file_read": matches(
            "readfile",
            "readfileex",
            "ntreadfile",
            "fread",
            "sqlite3_open",
            "sqlite3_open_v2",
        ),
        "decrypt": matches("cryptunprotectdata", "ncryptunprotectsecret"),
        "file_write": write,
        "network_retrieve": matches(
            "urldownloadtofilea",
            "urldownloadtofilew",
            "internetreadfile",
            "winhttpreaddata",
            "recv",
        ),
        "network_send": matches(
            "httpsendrequesta",
            "httpsendrequestw",
            "winhttpsendrequest",
            "winhttpwritedata",
            "send",
            "wsasend",
        ),
        "process_execute": matches(
            "createprocessa",
            "createprocessw",
            "createprocessasuserw",
            "winexec",
            "shellexecutea",
            "shellexecutew",
            "shellexecuteexa",
            "shellexecuteexw",
        ),
        "registry_write": matches("regsetvalueexa", "regsetvalueexw", "ntsetvaluekey"),
        "autorun": hits.get("autorun", []),
        "startup": hits.get("startup", []),
        "service_create": matches("createservicea", "createservicew"),
        "service_manager": matches("openscmanagera", "openscmanagerw"),
        "service_config": matches(
            "changeserviceconfiga",
            "changeserviceconfigw",
            "changeserviceconfig2a",
            "changeserviceconfig2w",
        ),
        "suspicious_executable_path": hits.get("suspicious_executable_path", []),
        "scheduled_task": hits.get("scheduled_task", []),
        "suspicious_shell": hits.get("suspicious_shell", []),
        "download_execute": hits.get("download_execute", []),
        "debug_check": debug,
        "multiple_debug_checks": debug if len(debug) >= 2 else [],
        "timing_or_vm": matches(
            "queryperformancecounter", "gettickcount", "gettickcount64"
        )
        or hits.get("vm_artifact", []),
        "vm_artifacts": hits.get("vm_artifact", [])
        if len(set(hits.get("vm_artifact", []))) >= 2
        else [],
        "system_discovery": matches(
            "createtoolhelp32snapshot",
            "enumprocesses",
            "regqueryvalueexa",
            "regqueryvalueexw",
        ),
    }


def packing_facts(report):
    apis = import_names(report)
    sections = report.get("file", {}).get("sections", [])
    return {
        "packer_sections": [
            s["name"]
            for s in sections
            if re.match(
                r"(?i)^(?:upx[0-9!]|\.aspack|\.adata|\.vmp[0-9])", s.get("name", "")
            )
        ],
        "high_entropy_code": [
            s["name"]
            for s in sections
            if s.get("executable")
            and s.get("raw_size", 0) >= 512
            and s.get("entropy", 0) >= 7.2
        ],
        "rwx": [
            s["name"] for s in sections if s.get("executable") and s.get("writable")
        ],
        "sparse_imports": len(apis) < 15,
        "dynamic_resolution": sorted(
            apis & {"getprocaddress", "ldrgetprocedureaddress"}
        )
        if apis
        & {
            "loadlibrarya",
            "loadlibraryw",
            "loadlibraryexa",
            "loadlibraryexw",
            "ldrloaddll",
        }
        else [],
    }


def is_packed(facts):
    return bool(
        facts["packer_sections"]
        or (
            facts["high_entropy_code"]
            and (
                facts["rwx"]
                or (facts["sparse_imports"] and facts["dynamic_resolution"])
            )
        )
    )


def detect_features(report):
    features = correlate_capabilities(native_capabilities(report), "outer_pe")
    features.extend(script_findings(report.get("payload_inspection")))
    for inspection in report.get("resources", {}).get("inspections", []):
        features.extend(script_findings(inspection))
    facts = packing_facts(report)

    def info(identifier, reason, evidence):
        features.append(
            {
                "id": identifier,
                "family": "visibility",
                "strength": "informational",
                "reason": reason,
                "base_points": 0.0,
                "evidence": evidence,
            }
        )

    if facts["rwx"]:
        info(
            "rwx_sections",
            "Writable executable sections; permissions alone do not establish malware",
            {"sections": facts["rwx"]},
        )
    if is_packed(facts):
        info(
            "packed_layout",
            "Packing conceals native capabilities; unpacking was not performed",
            facts,
        )
    if facts["dynamic_resolution"]:
        info(
            "dynamic_resolution",
            "Dynamic API resolution is common in ordinary software",
            {"imports": facts["dynamic_resolution"]},
        )
    signature = report.get("signature", {})
    if signature.get("integrity") == "INVALID":
        features.append(
            {
                "id": "signature_integrity",
                "family": "integrity",
                "strength": "moderate",
                "reason": "Authenticode digest or signature verification failed",
                "base_points": 3.0,
                "evidence": {"checks": signature.get("checks", [])},
            }
        )
    return features
