from os import getenv


def _get_env_var(var: str) -> str:
    value: str = getenv(var, "")
    if not value:
        raise ValueError(f"{var} is missing from the environment")
    return value


API_TOKEN: str = _get_env_var("API_TOKEN")
WEBSOCKET_HOST: str = _get_env_var("WEBSOCKET_HOST")
WEBSOCKET_PORT: int = int(_get_env_var("WEBSOCKET_PORT"))
TIMEOUT = 5
CHUNK_SIZE = 1024
