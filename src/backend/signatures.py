"""Issuer recognition for scoring, separate from OS chain/revocation validation."""

import re

# Explicit code-signing issuer names, never the executable's claimed publisher.
TRUSTED_ISSUERS = frozenset(
    {
        "digicert trusted g4 code signing rsa4096 sha384 2021 ca1",
        "digicert sha2 assured id code signing ca",
        "digicert sha2 extended validation code signing ca",
        "microsoft code signing pca 2011",
        "microsoft windows production pca 2011",
        "globalsign gcc r45 codesigning ca 2020",
        "sectigo public code signing ca r36",
    }
)


def recognized_issuer(issuer):
    match = re.search(r"(?:^|,\s*)CN=([^,]+)", issuer, re.IGNORECASE)
    return bool(match and match.group(1).strip().casefold() in TRUSTED_ISSUERS)


def signature_state(signature):
    integrity = signature.get("integrity", "UNKNOWN")
    recognized = bool(signature.get("known_ca")) or any(
        recognized_issuer(p.get("issuer", "")) for p in signature.get("publishers", [])
    )
    if signature.get("revocation") == "REVOKED":
        return "invalid"
    if integrity == "VALID":
        if signature.get("chain_trust") == "TRUSTED":
            return "trusted_signed"
        return "recognized_signed" if recognized else "valid_unrecognized"
    return {"UNSIGNED": "unsigned", "INVALID": "invalid"}.get(integrity, "unknown")
