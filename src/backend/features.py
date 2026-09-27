"""Semantic static capabilities, not claims that a behavior actually ran."""

import re
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
    "url": r"(?i)\bhttps?://[^\s\"'<>]{4,250}",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domain": r"(?i)\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top)\b",
}


def import_names(report):
    return {name.lower() for lib in report.get("imports", {}).get("libraries", [])
            for name in lib.get("functions", []) if name}


def detect_features(report):
    apis = import_names(report)
    hits = report.get("strings", {}).get("matches", {})
    features = []
    features.extend(script_findings(report.get("payload_inspection")))

    def matches(*names):
        return sorted(apis.intersection(names))

    def strings(category):
        return hits.get(category, [])

    def add(identifier, family, strength, reason, evidence):
        features.append(dict(id=identifier, family=family, strength=strength,
                             reason=reason, evidence=evidence))

    writer = matches("writeprocessmemory", "ntwritevirtualmemory", "zwwritevirtualmemory")
    allocator = matches("virtualallocex", "ntallocatevirtualmemory", "zwallocatevirtualmemory")
    remote_thread = matches("createremotethread", "createremotethreadex", "ntcreatethreadex")
    thread_context = matches("setthreadcontext", "ntsetcontextthread")
    resume = matches("resumethread", "ntresumethread")
    access = matches("openprocess", "ntopenprocess")
    apc = matches("queueuserapc", "ntqueueapcthread")
    if allocator and writer and (remote_thread or (thread_context and resume) or (apc and access)):
        add("injection_chain", "injection", "strong", "Remote allocation, memory write and execution capabilities coexist",
            {"imports": sorted(set(allocator + writer + remote_thread + thread_context + resume + apc + access)),
             "limitation": "Import co-occurrence does not establish common target handles or call order; debuggers and game tools can match."})

    decrypt = matches("cryptunprotectdata", "ncryptunprotectsecret")
    file_read = matches("readfile", "fread", "sqlite3_open", "sqlite3_open_v2")
    if strings("browser_database") and strings("browser_path") and decrypt and file_read:
        add("browser_credentials", "credentials", "moderate", "Browser storage paths, database names, reads and decryption coexist",
            {"paths": strings("browser_path"), "databases": strings("browser_database"), "imports": decrypt + file_read,
             "limitation": "Browsers and migration/backup tools can legitimately match."})

    reg_write = matches("regsetvalueexa", "regsetvalueexw", "ntsetvaluekey")
    if reg_write and strings("autorun"):
        add("autorun_write", "persistence", "moderate", "Autorun registry path plus registry writing capability",
            {"imports": reg_write, "strings": strings("autorun")})
    service = matches("createservicea", "createservicew")
    manager = matches("openscmanagera", "openscmanagerw")
    if service and manager:
        add("service_creation", "persistence", "weak", "Service manager and service creation capabilities (also common in installers)", {"imports": service + manager})
    execute = matches("createprocessa", "createprocessw", "winexec", "shellexecutea", "shellexecutew", "shellexecuteexa", "shellexecuteexw")
    writes = matches("writefile", "fwrite", "copyfilea", "copyfilew")
    if writes and strings("startup"):
        add("startup_write", "persistence", "moderate", "Startup folder path and file writing capability", {"imports": writes, "strings": strings("startup")})
    if execute and strings("scheduled_task"):
        add("scheduled_task", "persistence", "moderate", "Scheduled task creation command with action and execution capability", {"imports": execute, "strings": strings("scheduled_task")})
    if execute and strings("suspicious_shell"):
        add("suspicious_shell", "execution", "moderate", "Obfuscated/hidden shell command and process execution capability", {"imports": execute, "strings": strings("suspicious_shell")})
    if execute and strings("download_execute"):
        add("script_download_execute", "execution", "strong", "Script expression downloads and evaluates content", {"imports": execute, "strings": strings("download_execute")})
    download = matches("urldownloadtofilea", "urldownloadtofilew")
    if download and execute and strings("url"):
        add("download_launch", "execution", "weak", "Download-to-file and launch capabilities (common in updaters)", {"imports": download + execute, "urls": strings("url")})

    debug = matches("isdebuggerpresent", "checkremotedebuggerpresent")
    query = matches("ntqueryinformationprocess")
    if debug and query:
        add("anti_debug", "anti_analysis", "weak", "Debugger checks and process-information query coexist", {"imports": debug + query})
    discovery = matches("createtoolhelp32snapshot", "enumprocesses", "regqueryvalueexa", "regqueryvalueexw")
    if len(strings("vm_artifact")) >= 2 and discovery:
        add("anti_vm", "anti_analysis", "weak", "Multiple virtualization artifact strings and discovery capability", {"imports": discovery, "strings": strings("vm_artifact")})

    sections = report.get("file", {}).get("sections", [])
    metadata = report.get("file", {})
    overlay = metadata.get("overlay")
    # Older unsigned reports contain enough section offsets to expose this
    # coverage gap without reopening the input binary.
    if overlay is None and report.get("signature", {}).get("integrity") == "UNSIGNED" and sections and all("raw_offset" in s for s in sections):
        end = max(s["raw_offset"] + s.get("raw_size", 0) for s in sections)
        size = metadata.get("file_size", 0)
        payload = max(0, size - end)
        overlay = {"offset": end, "payload_bytes": payload,
                   "payload_fraction": payload / size if size else 0,
                   "source": "inferred from saved unsigned PE metadata"}
    if overlay and overlay.get("payload_bytes", 0) >= 65536 and overlay.get("payload_fraction", 0) >= 0.1:
        add("uninspected_payload", "coverage", "informational",
            "Substantial appended content has incomplete analysis coverage; outer PE capabilities cannot establish payload safety",
            overlay)
    rwx = [s["name"] for s in sections if s.get("executable") and s.get("writable")]
    packed = [s["name"] for s in sections if s.get("executable") and s.get("raw_size", 0) >= 512 and s.get("entropy", 0) >= 7.2]
    packer = [s["name"] for s in sections if re.match(r"(?i)^(?:upx[0-9!]|\.aspack|\.adata|\.vmp[0-9])", s["name"])]
    resolver = matches("getprocaddress", "ldrgetprocedureaddress")
    loader = matches("loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw", "ldrloaddll")
    sparse = len(apis) < 15
    if rwx:
        add("rwx_sections", "packing", "weak", "Writable executable sections", {"sections": rwx})
    if packer or (packed and (rwx or (sparse and resolver and loader))):
        add("packed_layout", "packing", "moderate", "Packer-like section layout limits visibility into code", {"packer_sections": packer, "high_entropy_code": packed, "rwx": rwx, "sparse_imports": sparse})
    if resolver and loader:
        add("dynamic_resolution", "packing", "informational", "Dynamic import resolution capability; common in legitimate software", {"imports": resolver + loader})
    abnormal = [s["name"] for s in sections if s.get("raw_out_of_bounds")]
    if abnormal:
        add("invalid_section_range", "packing", "moderate", "Section raw data extends outside file", {"sections": abnormal})
    signature = report.get("signature", {})
    if signature.get("integrity") == "INVALID":
        add("signature_integrity", "signature", "strong", "Authenticode digest or cryptographic signature integrity failed", {"checks": signature.get("checks", [])})
    return features
