
from os import getenv


def _get_env_var(var: str) -> str:
    value: str = getenv(var, "")
    if not value:
        raise ValueError(f"{var} is missing from the environment")
    return value


API_TOKEN = _get_env_var("API_TOKEN")

CHUNK_SIZE = 256
