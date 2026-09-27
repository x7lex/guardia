"""Rescore complete diagnostic fixtures; optionally statically rescan original PEs."""
import argparse
import asyncio
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from backend.analyzer import output
from backend.risk_score import calculate_risk


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples-dir", type=Path, help="Optional directory of original PEs; they are parsed, never executed")
    parser.add_argument("--output", type=Path, default=ROOT / "docs" / "diagnostics")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    summary = []
    for fixture in sorted((ROOT / "tests" / "fixtures" / "reports").glob("*.json")):
        saved = json.loads(fixture.read_text())
        original = saved["risk_assessment"]
        assessment = calculate_risk(saved["analysis"])
        name = saved["analysis"]["file"]["file_name"]
        rescored = {"analysis": saved["analysis"], "risk_assessment": assessment}
        (args.output / (fixture.stem + "-rescored.json")).write_text(json.dumps(rescored, indent=2) + "\n")
        row = {"sample": name, "fixture": fixture.name, "old_risk": original["risk"],
               "rescored_risk": assessment["risk"], "rescored_visibility": assessment["visibility"]["level"],
               "role": assessment["context"]["likely_role"]}
        if args.samples_dir:
            analysis = await output(args.samples_dir / Path(name).name)
            fresh = calculate_risk(analysis)
            (args.output / (fixture.stem + "-fresh.json")).write_text(json.dumps({"analysis": analysis, "risk_assessment": fresh}, indent=2) + "\n")
            row.update(fresh_risk=fresh["risk"], fresh_visibility=fresh["visibility"]["level"])
        summary.append(row)
        print(name, "saved facts:", assessment["risk"]["score"], assessment["risk"]["verdict"],
              "fresh:" if args.samples_dir else "", row.get("fresh_risk", {}).get("score", ""))
    (args.output / "comparison.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    asyncio.run(main())
