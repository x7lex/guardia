"""Entry point for the bundled scanner; never executes uploaded files."""
import asyncio
import multiprocessing

from backend.api import start_server
from logger import start_logger


if __name__ == "__main__":
    multiprocessing.freeze_support()
    start_logger()
    asyncio.run(start_server())
