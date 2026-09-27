"""Optional local YARA rules; never fetch rules or submit samples remotely."""
import hashlib
from os import getenv
from pathlib import Path


def inspect_yara(path):
    configured = getenv("YARA_RULES_PATH")
    if not configured:
        return {"status": "disabled", "matches": []}
    try:
        import yara
    except ImportError:
        return {"status": "unavailable", "matches": [], "reason": "Install optional yara-python to use configured rules"}
    try:
        source = Path(configured).read_bytes()
        if len(source) > 1024 * 1024:
            raise ValueError("Rule file too large")
        rules = yara.compile(source=source.decode("utf-8"), includes=False)
        matches = rules.match(filepath=str(path), timeout=5)
        return {"status": "complete", "rules_sha256": hashlib.sha256(source).hexdigest(),
                "matches": [{"rule": match.rule, "namespace": match.namespace, "tags": match.tags,
                             "meta": match.meta} for match in matches]}
    except Exception:
        # Optional inspection must not discard otherwise useful static analysis.
        return {"status": "unavailable", "matches": [], "reason": "YARA rules could not be loaded or inspection failed/timed out"}
