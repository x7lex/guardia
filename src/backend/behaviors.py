"""Shared, source-local behavioral correlations for PE imports and script calls.

Facts establish capability co-occurrence, not execution, reachability or data flow.
No rule uses input names, hashes, import counts or publisher allowlists.
"""


def correlate_capabilities(facts, source, correlation="source-local co-occurrence"):
    findings = []

    def add(identifier, family, strength, reason, required, points, contextual=False):
        if all(facts.get(key) for key in required):
            findings.append(
                {
                    "id": identifier,
                    "family": family,
                    "strength": strength,
                    "reason": reason,
                    "base_points": points,
                    "contextual": contextual,
                    "evidence": {
                        "source": source,
                        "correlation": correlation,
                        "capabilities": {key: facts[key] for key in required},
                        "limitation": "Static evidence does not prove call order, common handles, reachability or observed behavior.",
                    },
                }
            )

    add(
        "injection_chain",
        "injection",
        "strong",
        "Process access, remote allocation, memory write and remote execution coexist",
        ["process_access", "remote_allocate", "remote_write", "remote_execute"],
        6.0,
    )
    add(
        "browser_credentials",
        "credentials",
        "strong",
        "Browser profiles, credential storage, data access and decryption coexist",
        ["browser_profile", "credential_storage", "file_read", "decrypt"],
        6.0,
    )
    if all(
        facts.get(key)
        for key in ("browser_profile", "credential_storage", "file_read", "decrypt")
    ):
        add(
            "credential_exfiltration",
            "exfiltration",
            "strong",
            "Credential access/decryption chain coexists with outbound data submission",
            [
                "browser_profile",
                "credential_storage",
                "file_read",
                "decrypt",
                "network_send",
            ],
            4.0,
        )
    add(
        "autorun_write",
        "persistence",
        "moderate",
        "Autorun location and registry writing coexist; target linkage is unproven",
        ["autorun", "registry_write"],
        1.5,
        True,
    )
    add(
        "startup_write",
        "persistence",
        "moderate",
        "Startup location and file writing coexist; target linkage is unproven",
        ["startup", "file_write"],
        1.5,
        True,
    )
    add(
        "service_creation",
        "persistence",
        "informational",
        "Service installation capability; expected in installers and system tools",
        ["service_create", "service_manager"],
        0.0,
        True,
    )
    add(
        "service_persistence",
        "persistence",
        "moderate",
        "Service creation/configuration coexists with an executable in a user-writable location",
        ["service_create", "service_config", "suspicious_executable_path"],
        2.5,
    )
    add(
        "scheduled_task",
        "persistence",
        "moderate",
        "A task-creation command specifies an action and process execution is available",
        ["scheduled_task", "process_execute"],
        2.5,
    )
    add(
        "download_launch",
        "execution",
        "weak",
        "Network retrieval, file creation/write and process execution coexist",
        ["network_retrieve", "file_write", "process_execute"],
        1.0,
        True,
    )
    add(
        "suspicious_shell",
        "execution",
        "moderate",
        "Hidden/encoded shell command and process execution coexist",
        ["suspicious_shell", "process_execute"],
        2.5,
    )
    add(
        "script_download_execute",
        "execution",
        "strong",
        "A download-and-evaluate expression has an execution sink",
        ["download_execute", "process_execute"],
        4.0,
    )
    add(
        "anti_debug_probe",
        "anti_analysis",
        "informational",
        "An isolated debugger API is not an evasion chain",
        ["debug_check"],
        0.0,
    )
    add(
        "anti_analysis_checks",
        "anti_analysis",
        "weak",
        "Multiple debugger checks coexist with timing or VM discovery checks",
        ["multiple_debug_checks", "timing_or_vm"],
        1.0,
    )
    add(
        "anti_vm",
        "anti_analysis",
        "weak",
        "Multiple virtualization artifact strings coexist with discovery capability",
        ["vm_artifacts", "system_discovery"],
        0.5,
    )
    return findings
