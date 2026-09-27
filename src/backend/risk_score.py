from enum import IntEnum
from typing import Any

class RiskPoints(IntEnum):
    GOOD_SIGNATURE = -3
    USER_ELEVATION = 1
    SUSPICIOUS_IMPORT_SEQUENCE = 1
    BAD_SIGNATURE = 2
    SUSPICIOUS_CPU_INSTRUCTIONS = 3
    UNSIGNED = 4
    SENSITIVE_METADATA = 5


def get_risk_level(points: int) -> str:
    if points <= 3:
        return "Safe"

    if points <= 6:
        return "Risky"

    if points <= 8:
        return "Unsafe"

    return "Dangerous"


# points * 10 -> risk %
def calculate_risk(
    report: dict[str, Any],
    user_elevation: bool = False,
    suspicious_import_sequence: bool = False,
    sensitive_metadata: bool = False,
) -> dict:

    points = 0
    reasons = []

    signature = report.get("signature", {})
    instructions = report.get("suspicious_instructions", {})

    if not signature.get("signed", False):
        points += RiskPoints.UNSIGNED

        reasons.append({
            "reason": "Unsigned executable",
            "points": RiskPoints.UNSIGNED,
        })

    elif (
        signature.get("integrity") == "VALID"
        and signature.get("known_ca", False)
    ):
        points += RiskPoints.GOOD_SIGNATURE

        reasons.append({
            "reason": "Valid signature from known CA",
            "points": RiskPoints.GOOD_SIGNATURE,
        })

    else:
        points += RiskPoints.BAD_SIGNATURE

        reasons.append({
            "reason": "Invalid or untrusted signature",
            "points": RiskPoints.BAD_SIGNATURE,
        })

    if user_elevation:
        points += RiskPoints.USER_ELEVATION

        reasons.append({
            "reason": "Requests user elevation",
            "points": RiskPoints.USER_ELEVATION,
        })

    if suspicious_import_sequence:
        points += RiskPoints.SUSPICIOUS_IMPORT_SEQUENCE

        reasons.append({
            "reason": "Suspicious import sequence detected",
            "points": RiskPoints.SUSPICIOUS_IMPORT_SEQUENCE,
        })

    if instructions.get("count", 0) > 0:
        points += RiskPoints.SUSPICIOUS_CPU_INSTRUCTIONS

        reasons.append({
            "reason": "Suspicious CPU instructions detected",
            "points": RiskPoints.SUSPICIOUS_CPU_INSTRUCTIONS,
            "instructions": instructions.get("instructions", []),
        })

    if sensitive_metadata:
        points += RiskPoints.SENSITIVE_METADATA

        reasons.append({
            "reason": "Sensitive folder or cookie access detected",
            "points": RiskPoints.SENSITIVE_METADATA,
        })

    points = max(0, min(int(points), 10))

    return {
        "file_name": report["file"]["file_name"],
        "sha256": report["file"]["sha256"],
        "risk": {
            "points": points,
            "percentage": points * 10,
            "level": get_risk_level(points),
        },
        "reasons": reasons,
    }
