from asyncio import run
from logging import Logger, getLogger

from backend.websocket import start_websocket
from logger import start_logger

start_logger()
logger: Logger = getLogger(name="Main")


async def main():
    await start_websocket()


if __name__ == "__main__":
    run(main())
