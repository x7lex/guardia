"""HTTP interface for browser uploads. Target files are never executed."""

import asyncio
import json
import logging
from os import getenv
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from uvicorn import Config, Server

from backend.analyzer import MAX_FILE_BYTES, UnsupportedFileError, output
from backend.gemini_review import review_report
from backend.risk_score import calculate_risk

load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)
MAX_REVIEW_BYTES = 4 * 1024 * 1024

app = FastAPI(title="Guardia scanner")
logger = logging.getLogger(__name__)
# Keep the parser's peak memory bounded, even across multiple browser tabs.
scan_lock = asyncio.Lock()


@app.get("/health")
async def health():
    return {"status": "ok", "max_file_bytes": MAX_FILE_BYTES}


def upload_name(value: str) -> str:
    value = value.replace("\\", "/")
    parts = value.split("/")
    if (
        not value
        or len(value) > 2048
        or value.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(char) < 32 for char in value)
        or ":" in value
    ):
        raise HTTPException(400, "Provide a valid relative file name")
    return str(PurePosixPath(value))


@app.post("/scan")
async def scan(request: Request, name: str):
    name = upload_name(name)
    if (
        request.headers.get("content-type", "").split(";")[0]
        != "application/octet-stream"
    ):
        raise HTTPException(415, "Send the file as application/octet-stream")
    length = request.headers.get("content-length")
    if length is not None:
        if not length.isdigit():
            raise HTTPException(400, "Invalid Content-Length")
        if int(length) > MAX_FILE_BYTES:
            raise HTTPException(413, "File exceeds the 512 MiB scan limit")

    async with scan_lock:
        with TemporaryDirectory(prefix="guardia-") as directory:
            # User-supplied paths are display metadata only, never disk paths.
            target = Path(directory) / "upload.bin"
            size = 0
            with target.open("wb") as destination:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > MAX_FILE_BYTES:
                        raise HTTPException(413, "File exceeds the 512 MiB scan limit")
                    destination.write(chunk)
            if not size:
                return {"status": "skipped", "file": name, "reason": "File is empty"}
            try:
                analysis = await output(target)
                analysis["file"].update(
                    file_name=PurePosixPath(name).name, file_path=name
                )
                report = {
                    "analysis": analysis,
                    "risk_assessment": calculate_risk(analysis),
                }
                return {"status": "scanned", "file": name, "report": report}
            except UnsupportedFileError as error:
                return {"status": "skipped", "file": name, "reason": str(error)}
            except Exception:
                logger.exception("Static analysis failed for uploaded file")
                raise HTTPException(
                    500, "The scanner could not analyze this file"
                ) from None


@app.post("/review")
async def review(request: Request):
    if request.headers.get("content-type", "").split(";")[0] != "application/json":
        raise HTTPException(415, "Send the scan report as application/json")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_REVIEW_BYTES:
            raise HTTPException(413, "The report exceeds the 4 MiB Gemini review limit")
    try:
        report = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise HTTPException(400, "Provide a valid JSON scan report") from None
    if (
        not isinstance(report, dict)
        or not isinstance(report.get("analysis"), dict)
        or not isinstance(report["analysis"].get("file"), dict)
        or not isinstance(report.get("risk_assessment"), dict)
        or not isinstance(report["risk_assessment"].get("risk"), dict)
    ):
        raise HTTPException(
            400, "The report must contain analysis.file and risk_assessment.risk"
        )
    return await review_report(report)


async def start_server():
    await Server(
        Config(
            app,
            host=getenv("BACKEND_HOST") or "127.0.0.1",
            port=int(getenv("BACKEND_PORT") or "8000"),
        )
    ).serve()
