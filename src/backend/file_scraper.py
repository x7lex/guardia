from logging import Logger, getLogger
from pathlib import Path

logger: Logger = getLogger(name="File Scraper")


def walk(path: str) -> list[Path]:
    root: Path = Path(path)
    filePaths: list[Path] = []
    logger.info(f"Directory path: {root}")
    for dirPath, dirNames, fileNames in root.walk():
        logger.info(f"Subdirectory path: {dirPath}")
        for fileName in fileNames:
            filePath: Path = dirPath / fileName
            filePaths.append(filePath)
            logger.info(f"File path: {filePath}")
    return filePaths
