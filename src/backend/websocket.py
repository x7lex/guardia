from contextlib import asynccontextmanager
from logging import getLogger

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from httpx import AsyncClient
from uvicorn import Config, Server

from constants import TIMEOUT, WEBSOCKET_HOST, WEBSOCKET_PORT

logger = getLogger(name="Websocket")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing websocket")
    app.state.websocket = AsyncClient(timeout=TIMEOUT)
    logger.info("Initialized websocket")
    yield
    logger.info("Closing websocket client")
    await app.state.websocket.aclose()
    logger.info("Closed websocket client")


app = FastAPI(lifespan=lifespan)


async def start_websocket() -> None:
    logger.info(f"Starting websocket on {WEBSOCKET_HOST}:{WEBSOCKET_PORT}")
    config = Config(app, host=WEBSOCKET_HOST, port=WEBSOCKET_PORT, log_level="warning")
    server = Server(config)
    await server.serve()


@app.websocket("/path")
async def websocket_path(websocket: WebSocket) -> None:
    await websocket.accept()
    logger.info("Websocket client connected")
    try:
        while True:
            payload = await websocket.receive()
            path = payload.get("path")
            if path is None:
                await websocket.send_json(
                    {"status": "Error", "message": "Missing path in payload"}
                )
                continue
            logger.info(f"Received path: {path}")
            await websocket.send_json({"status": "Received"})
    except WebSocketDisconnect:
        logger.info("Websocket client disconnected")
