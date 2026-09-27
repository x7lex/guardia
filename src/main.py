"""CLI for static PE triage; reports stay under the project directory."""

import argparse
import asyncio
import json
from datetime import datetime, timezone
from logging import getLogger
from pathlib import Path

from backend.analyzer import UnsupportedFileError, output
from backend.risk_score import calculate_risk
from logger import start_logger

logger = getLogger("Main")


def get_reports_directory():
    directory = Path(__file__).resolve().parent / "reports"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def get_target(value=None):
    if value is None:
        value = input("enter a file or directory to scan: ")
    path = Path(value.strip().strip('"').strip("'")).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")
    return path


def save_report(report, report_directory=None, timestamp=None):
    directory = report_directory or get_reports_directory()
    directory.mkdir(parents=True, exist_ok=True)
    timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S_%f")
    # Retain the extension so same-stem EXE/DLL inputs cannot overwrite each other.
    name = Path(report["analysis"]["file"]["file_name"]).name
    path = directory / f"{name}_{timestamp}.json"
    path.write_text(json.dumps(report, indent=4), encoding="utf-8")
    logger.info("Report saved: %s", path)
    return path


async def scan_file(target_file, report_directory=None, timestamp=None):
    try:
        analysis = await output(target_file)
        risk = calculate_risk(analysis)
        report_path = save_report({"analysis": analysis, "risk_assessment": risk}, report_directory, timestamp)
        print(f"[+] Scanned: {target_file.name}\n    Risk: {risk['risk']['score']} ({risk['risk']['verdict']})\n    Report: {report_path}")
        print(f"    Threat evidence: {risk['risk']['threat_points']}/10; visibility: {risk['visibility']['level']} ({risk['visibility']['score']}); role: {risk['context']['likely_role']}")
        if risk["diagnostics"]["assessment"] == "limited_visibility":
            print("    Coverage limited; inspect report diagnostics.")
        return {"file": target_file.name, "status": "scanned", "report": str(report_path)}
    except UnsupportedFileError as error:
        print(f"[~] Skipped: {target_file.name} -> {error}")
        return {"file": target_file.name, "status": "skipped", "reason": str(error)}
    except Exception as error:
        logger.error("Failed to scan %s: %s", target_file.name, error)
        print(f"[-] Failed: {target_file.name} -> {error}")
        return {"file": target_file.name, "status": "error", "reason": str(error)}


async def scan_directory(directory):
    files = sorted(path for path in directory.iterdir() if path.is_file() and not path.is_symlink())
    if not files:
        print("No regular files found in directory")
        return
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S_%f")
    report_directory = get_reports_directory() / f"{directory.name}_{timestamp}"
    report_directory.mkdir(parents=True, exist_ok=True)
    # Serial parsing bounds peak memory for large installers.
    for path in files:
        await scan_file(path, report_directory, timestamp)


async def main():
    start_logger()
    parser = argparse.ArgumentParser(description="Statically scan PE files or start the web app API.")
    parser.add_argument("target", nargs="?", help="File or directory; prompts if omitted")
    parser.add_argument("--serve", "--websocket", dest="serve", action="store_true", help="Start the HTTP upload API (default: 127.0.0.1:8000)")
    parser.add_argument("--rescore-report", type=Path, help="Rescore saved JSON facts without reopening the binary")
    args = parser.parse_args()
    if args.serve:
        from backend.api import start_server
        await start_server()
        return
    try:
        if args.rescore_report:
            report = json.loads(args.rescore_report.read_text(encoding="utf-8"))
            risk = calculate_risk(report["analysis"])
            report["risk_assessment"] = risk
            path = save_report(report)
            print(f"{risk['risk']['score']} ({risk['risk']['verdict']})\nReport: {path}")
            return
        target = get_target(args.target)
        if target.is_file():
            await scan_file(target)
        elif target.is_dir():
            await scan_directory(target)
        else:
            print("Target is not a regular file or directory")
    except (OSError, ValueError) as error:
        logger.error("Scan failed: %s", error)
        print(f"[-] {error}")


if __name__ == "__main__":
    asyncio.run(main())
