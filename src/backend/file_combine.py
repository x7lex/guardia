from json import dumps
from logging import Logger, getLogger
from pathlib import Path

from constants import CHUNK_SIZE

logger: Logger = getLogger(name="File Combine")


def combine_json(filePaths: list[Path], outputFilePath: Path) -> None:
    with open(outputFilePath, "w") as output:
        logger.info("Combining json files")
        first: bool = True
        output.write("{\n")
        for filePath in filePaths:
            try:
                with open(filePath, mode="r") as input:
                    if not first:
                        output.write(",\n")
                    else:
                        first = False
                    key: str = dumps(str(filePath))
                    output.write(f"  {key}: ")
                    while chunk := input.read(CHUNK_SIZE):
                        output.write(chunk)
            except (OSError, UnicodeDecodeError) as e:
                logger.error(f"Could not combine {filePath}, skipping: {e}")
        output.write("\n}\n")
        logger.info(f"Combined json file written to {outputFilePath}")
