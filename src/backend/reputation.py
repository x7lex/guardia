"""Optional, hash-only reputation. No file upload or download endpoints exist here."""

import asyncio
import re
from datetime import datetime, timezone
from os import getenv

import httpx

PROVIDERS = {"malwarebazaar", "virustotal"}


def _result(sha256, provider, status, reason, **evidence):
    return {
        "sha256": sha256,
        "provider": provider,
        "status": status,
        "reason": reason,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "hash_only": True,
        "evidence": evidence,
    }


def classify_response(sha256, provider, body):
    """Reject mismatched identities; no detections is never a clean verdict."""
    if provider == "malwarebazaar":
        if body.get("query_status") == "hash_not_found":
            return _result(
                sha256,
                provider,
                "unknown",
                "Hash not found; this does not establish safety",
            )
        rows = body.get("data", [])
        if body.get("query_status") != "ok" or not isinstance(rows, list):
            raise ValueError("Invalid provider response")
        row = next(
            (
                row
                for row in rows
                if isinstance(row, dict)
                and row.get("sha256_hash", "").lower() == sha256
            ),
            None,
        )
        if not row:
            raise ValueError("No exact SHA-256 match")
        return _result(
            sha256,
            provider,
            "known_malicious",
            "Exact SHA-256 record in MalwareBazaar's malware collection",
            matched_sha256=sha256,
            basis="malware_collection_match",
            signature=row.get("signature"),
            first_seen=row.get("first_seen"),
            last_seen=row.get("last_seen"),
        )
    data = body["data"]
    if data.get("type") != "file" or data.get("id", "").lower() != sha256:
        raise ValueError("No exact SHA-256 match")
    attrs = data["attributes"]
    raw = attrs["last_analysis_stats"]
    stats = {
        k: raw.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")
    }
    if any(type(v) is not int or v < 0 for v in stats.values()):
        raise ValueError("Invalid detection statistics")
    total = sum(stats.values())
    classification = attrs.get("popular_threat_classification") or {}
    labels = [str(classification.get("suggested_threat_label", ""))] + [
        str(item.get("value", ""))
        for item in classification.get("popular_threat_category", [])
        if isinstance(item, dict)
    ]
    dual_use = any(
        re.search(
            r"(?i)(?:^|[^a-z])(hacktool|riskware|pua|pup|adware|cheat)(?:[^a-z]|$)",
            label,
        )
        for label in labels
    )
    evidence = {
        "matched_sha256": sha256,
        "stats": stats,
        "last_analysis_date": attrs.get("last_analysis_date"),
        "provider_threat_labels": labels,
        "potentially_unwanted_or_dual_use": dual_use,
    }
    # A handful of generic/PUP detections is not a confirmed-malware override.
    if (
        not dual_use
        and stats["malicious"] >= 10
        and stats["malicious"] / max(1, total) >= 0.25
    ):
        return _result(
            sha256,
            provider,
            "known_malicious",
            "At least 10 malicious engines and 25% of completed verdicts",
            basis="multi_engine_consensus",
            **evidence,
        )
    if dual_use:
        return _result(
            sha256,
            provider,
            "unknown",
            "Provider categorizes this hash as potentially unwanted or dual-use; not a confirmed-malware override",
            **evidence,
        )
    votes = attrs.get("total_votes", {})
    reputation = attrs.get("reputation", 0)
    if (
        total >= 20
        and stats["malicious"] == stats["suspicious"] == 0
        and isinstance(reputation, (int, float))
        and reputation >= 100
        and isinstance(votes.get("harmless"), int)
        and votes["harmless"] >= 10
        and votes.get("malicious", 0) == 0
    ):
        return _result(
            sha256,
            provider,
            "reputable",
            "Positive community reputation corroborated by at least 20 non-detecting engines; not certified clean",
            basis="corroborated_positive_reputation",
            community_reputation=reputation,
            votes=votes,
            **evidence,
        )
    return _result(
        sha256,
        provider,
        "unknown",
        "No strong reputation conclusion; sparse detections or non-detection alone are inconclusive",
        **evidence,
    )


async def lookup_hash(sha256):
    sha256 = str(sha256 or "").lower()
    provider = getenv("REPUTATION_PROVIDER", "disabled").lower()
    if provider in {"", "disabled", "none"}:
        return _result(sha256, "none", "disabled", "Hash reputation is disabled")
    if provider not in PROVIDERS:
        return _result(
            sha256, provider, "unavailable", "Unsupported reputation provider"
        )
    if not re.fullmatch(r"[a-f0-9]{64}", sha256):
        return _result(sha256, provider, "unavailable", "A valid SHA-256 is required")
    key_name = (
        "MALWAREBAZAAR_API_KEY" if provider == "malwarebazaar" else "VIRUSTOTAL_API_KEY"
    )
    key = getenv(key_name)
    if not key:
        return _result(
            sha256, provider, "unavailable", f"Set {key_name} to enable lookup"
        )
    try:
        async with (
            asyncio.timeout(15),
            httpx.AsyncClient(timeout=15, follow_redirects=False) as client,
        ):
            if provider == "malwarebazaar":
                response = await client.post(
                    "https://mb-api.abuse.ch/api/v1/",
                    headers={"Auth-Key": key},
                    data={"query": "get_info", "hash": sha256},
                )
            else:
                response = await client.get(
                    f"https://www.virustotal.com/api/v3/files/{sha256}",
                    headers={"x-apikey": key},
                )
        if response.status_code == 429:
            return _result(
                sha256,
                provider,
                "rate_limited",
                "Reputation service rate limit reached",
            )
        if response.status_code == 404 and provider == "virustotal":
            return _result(
                sha256,
                provider,
                "unknown",
                "Hash not found; this does not establish safety",
            )
        if not response.is_success:
            return _result(
                sha256,
                provider,
                "unavailable",
                f"Reputation service returned HTTP {response.status_code}",
            )
        return classify_response(sha256, provider, response.json())
    except (
        httpx.RequestError,
        TimeoutError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    ):
        # Provider response bodies may contain secrets. Never echo them into reports.
        return _result(
            sha256,
            provider,
            "unavailable",
            "Reputation lookup failed or returned invalid evidence",
        )


def applicable_reputation(reputation, sha256):
    """Only exact, internally normalized provider evidence may affect scoring."""
    sha256 = str(sha256 or "").lower()
    if not isinstance(reputation, dict) or not re.fullmatch(r"[a-f0-9]{64}", sha256):
        return None
    evidence = reputation.get("evidence")
    if not isinstance(evidence, dict):
        return None
    if (
        reputation.get("sha256") != sha256
        or reputation.get("provider") not in PROVIDERS
        or evidence.get("matched_sha256") != sha256
    ):
        return None
    if reputation.get("status") == "known_malicious":
        if (
            reputation["provider"] == "malwarebazaar"
            and evidence.get("basis") == "malware_collection_match"
        ):
            return "known_malicious"
        if (
            reputation["provider"] == "virustotal"
            and evidence.get("basis") == "multi_engine_consensus"
            and not evidence.get("potentially_unwanted_or_dual_use")
        ):
            stats = evidence.get("stats", {})
            if not isinstance(stats, dict):
                return None
            counts = [
                stats.get(k, 0)
                for k in ("malicious", "suspicious", "harmless", "undetected")
            ]
            if (
                all(type(v) is int and v >= 0 for v in counts)
                and counts[0] >= 10
                and counts[0] / max(1, sum(counts)) >= 0.25
            ):
                return "known_malicious"
    if (
        reputation.get("status") == "reputable"
        and reputation["provider"] == "virustotal"
        and evidence.get("basis") == "corroborated_positive_reputation"
    ):
        # Reuse the same positive-evidence thresholds for imported reports.
        try:
            verdict = classify_response(
                sha256,
                "virustotal",
                {
                    "data": {
                        "type": "file",
                        "id": sha256,
                        "attributes": {
                            "last_analysis_stats": evidence.get("stats", {}),
                            "total_votes": evidence.get("votes", {}),
                            "reputation": evidence.get("community_reputation", 0),
                        },
                    }
                },
            )
        except (ValueError, TypeError, AttributeError):
            return None
        return "reputable" if verdict["status"] == "reputable" else None
    return None
