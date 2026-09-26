from logging import INFO, basicConfig


def start_logger():
    basicConfig(level=INFO, format="[%(levelname)s] %(name)s: %(message)s")
