from os import getenv


def _get_env_var(var: str) -> str:
    value: str = getenv(var, "")
    if not value:
        raise ValueError(f"{var} is missing from the environment")
    return value


API_TOKEN: str = _get_env_var("API_TOKEN")
BACKEND_WEBSOCKET_HOST: str = _get_env_var("BACKEND_WEBSOCKET_HOST")
BACKEND_WEBSOCKET_PORT: int = int(_get_env_var("BACKEND_WEBSOCKET_PORT"))
FRONTEND_WEBSOCKET_HOST: str = _get_env_var("FRONTEND_WEBSOCKET_HOST")
FRONTEND_WEBSOCKET_PORT: int = int(_get_env_var("FRONTEND_WEBSOCKET_PORT"))
CHUNK_SIZE = 1024
