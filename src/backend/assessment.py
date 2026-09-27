"""Compose three separate assessments for API, CLI and saved-report rescoring."""

from backend.gemini_review import attach_review
from backend.reputation import lookup_hash
from backend.risk_score import calculate_risk


async def build_report(analysis, *, review=True):
    reputation = await lookup_hash(analysis.get("file", {}).get("sha256"))
    report = {
        "analysis": analysis,
        "reputation": reputation,
        "risk_assessment": calculate_risk(analysis, reputation=reputation),
    }
    if review:
        await attach_review(report)
    return report
