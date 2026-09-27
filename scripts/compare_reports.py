"""Rescore complete diagnostic fixtures; optionally statically rescan original PEs."""

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from dotenv import load_dotenv

from backend.analyzer import output
from backend.assessment import build_report

load_dotenv(ROOT / ".env", override=False)


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--samples-dir",
        type=Path,
        help="Optional directory of original PEs; they are parsed, never executed",
    )
    parser.add_argument("--output", type=Path, default=ROOT / "docs" / "diagnostics")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    summary = []
    for fixture in sorted((ROOT / "tests" / "fixtures" / "reports").glob("*.json")):
        saved = json.loads(fixture.read_text())
        original = saved["risk_assessment"]
        rescored = await build_report(saved["analysis"])
        assessment = rescored["risk_assessment"]
        name = saved["analysis"]["file"]["file_name"]
        (args.output / (fixture.stem + "-rescored.json")).write_text(
            json.dumps(rescored, indent=2) + "\n"
        )
        row = {
            "sample": name,
            "fixture": fixture.name,
            "old_risk": original["risk"],
            "rescored_risk": assessment["risk"],
        }
        if args.samples_dir:
            analysis = await output(args.samples_dir / Path(name).name)
            fresh_report = await build_report(analysis)
            fresh = fresh_report["risk_assessment"]
            (args.output / (fixture.stem + "-fresh.json")).write_text(
                json.dumps(fresh_report, indent=2) + "\n"
            )
            row.update(
                fresh_risk=fresh["risk"],
                gemini_status=fresh_report["gemini_review"]["status"],
                gemini_verdict=fresh_report["gemini_review"].get("verdict"),
                heuristic=fresh["heuristic"],
                reputation=fresh_report["reputation"]["status"],
                decision_source=fresh["decision"]["source"],
            )
        summary.append(row)
        print(
            name,
            "saved facts:",
            assessment["risk"]["score"],
            assessment["risk"]["verdict"],
            "fresh:" if args.samples_dir else "",
            row.get("fresh_risk", {}).get("score", ""),
        )
    (args.output / "comparison.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    asyncio.run(main())
