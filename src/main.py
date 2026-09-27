import argparse
import asyncio
import json
from datetime import datetime, timezone
from logging import Logger, getLogger
from pathlib import Path

from backend.analyzer import output
from backend.risk_score import calculate_risk
from logger import start_logger

start_logger()
logger: Logger = getLogger(name="Main")


def get_reports_directory() -> Path:
    reports_dir = Path(__file__).resolve().parent / "reports"

    reports_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    return reports_dir


def get_target() -> Path:
    target = input("enter a file or directory to scan: ").strip()

    # Allows paths copied with quotes
    target = target.strip('"').strip("'")

    path = Path(target).expanduser().resolve()

    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")

    return path


def save_report(
    report: dict,
    report_directory: Path | None = None,
    timestamp: str | None = None,
) -> Path:
    if report_directory is None:
        report_directory = get_reports_directory()

    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")

    file_name = Path(report["analysis"]["file"]["file_name"]).stem

    report_path = report_directory / f"{file_name}_{timestamp}.json"

    with report_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
        )

    logger.info(
        "Report saved: %s",
        report_path,
    )

    return report_path


async def scan_file(
    target_file: Path,
    report_directory: Path | None = None,
    timestamp: str | None = None,
) -> None:
    logger.info(
        "Scanning: %s",
        target_file,
    )

    try:
        analysis = await output(target_file)

        risk = calculate_risk(
            analysis,
            user_elevation=False,
            suspicious_import_sequence=False,
            sensitive_metadata=False,
        )

        report = {
            "analysis": analysis,
            "risk_assessment": risk,
        }

        report_path = save_report(
            report,
            report_directory,
            timestamp,
        )

        # temp print stuff
        print(f"[+] Scanned: {target_file.name}")

        print(f"    Risk: {risk['risk']['percentage']}% ({risk['risk']['level']})")

        print(f"    Report: {report_path}")

    except Exception as error:
        logger.exception(
            "Failed to scan %s",
            target_file,
        )

        print(f"[-] failed: {target_file.name} -> {error}")


async def scan_directory(directory: Path) -> None:
    files = [path for path in directory.iterdir() if path.is_file()]

    if not files:
        print("no files found in directory")
        return

    print(f"\nfound {len(files)} file(s)\n")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")

    reports_dir = get_reports_directory()

    directory_report = reports_dir / f"{directory.name}_{timestamp}"

    directory_report.mkdir(
        parents=True,
        exist_ok=True,
    )

    await asyncio.gather(
        *[
            scan_file(
                target_file,
                report_directory=directory_report,
                timestamp=timestamp,
            )
            for target_file in files
        ]
    )


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan PE files or start the WebSocket server."
    )
    parser.add_argument(
        "--websocket", action="store_true", help="Start the WebSocket server"
    )
    args = parser.parse_args()
    if args.websocket:
        from backend.websocket import start_websocket

        await start_websocket()
        return

    try:
        target = get_target()

        if target.is_file():
            await scan_file(target)

        elif target.is_dir():
            await scan_directory(target)

        else:
            print("target is not a valid file or directory")

    except Exception:
        logger.exception("error")


if __name__ == "__main__":
    asyncio.run(main())
