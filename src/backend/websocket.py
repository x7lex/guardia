from json import dumps
from logging import Logger, getLogger
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from uvicorn import Config, Server
from websockets import connect

from constants import (
    BACKEND_WEBSOCKET_HOST,
    BACKEND_WEBSOCKET_PORT,
    FRONTEND_WEBSOCKET_HOST,
    FRONTEND_WEBSOCKET_PORT,
)

logger: Logger = getLogger(name="Websocket")

app = FastAPI()


async def start_websocket() -> None:
    logger.info(
        f"Starting websocket on {BACKEND_WEBSOCKET_HOST}:{BACKEND_WEBSOCKET_PORT}"
    )
    config = Config(
        app,
        host=BACKEND_WEBSOCKET_HOST,
        port=BACKEND_WEBSOCKET_PORT,
        log_level="warning",
    )
    server = Server(config)
    await server.serve()


@app.websocket("/path")
async def websocket_path(websocket: WebSocket) -> None:
    await websocket.accept()
    logger.info("Websocket /path client connected")
    try:
        while True:
            payload = await websocket.receive_json()
            path_str: str | None = payload.get("path")
            if path_str is None:
                await websocket.send_json(
                    {"status": "Error", "message": "Missing path in payload"}
                )
                continue
            path: Path = Path(path_str)
            logger.info(f"Received path: {path}")
            async with connect(
                f"ws://{FRONTEND_WEBSOCKET_HOST}:{FRONTEND_WEBSOCKET_PORT}/report"
            ) as report_websocket:
                report_payload: dict[str, Any] = {
                    "status": "Received",
                    "path": str(path),
                }
                await report_websocket.send(dumps(report_payload))
                logger.info(
                    f"Sent report to {FRONTEND_WEBSOCKET_HOST}:{FRONTEND_WEBSOCKET_PORT}/report"
                )
            await websocket.send_json({"status": "Received"})
    except WebSocketDisconnect:
        logger.info("Websocket /path client disconnected")
