"""Run Guardia in Electron, owning and cleaning up its local services."""
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "hackthehill3-website-final" / "website" / "scanly"


def port_is_open(port):
    with socket.socket() as connection:
        connection.settimeout(0.25)
        return connection.connect_ex(("127.0.0.1", port)) == 0


def responds(url):
    try:
        with urlopen(url, timeout=1):
            return True
    except OSError:
        return False


def main():
    load_dotenv(ROOT / ".env", override=False)
    env = os.environ.copy()
    web_port = int(env.get("DESKTOP_PORT", "3765"))
    api_port = int(env.get("DESKTOP_BACKEND_PORT", "8765"))
    npm = shutil.which("npm")
    if not npm or not (WEB / "node_modules/electron/dist").is_dir():
        raise SystemExit(f"Install desktop dependencies first: npm ci --prefix {WEB}")
    for port in (web_port, api_port):
        if port_is_open(port):
            raise SystemExit(f"Desktop port {port} is busy. Close the other desktop instance or set DESKTOP_PORT and DESKTOP_BACKEND_PORT.")
    url = f"http://127.0.0.1:{web_port}"
    env.update(BACKEND_HOST="127.0.0.1", BACKEND_PORT=str(api_port),
               BACKEND_URL=f"http://127.0.0.1:{api_port}",
               GUARDIA_DESKTOP_URL=url, GUARDIA_DESKTOP="1")
    env.pop("ELECTRON_RUN_AS_NODE", None)
    children = []

    def stop(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)

    def start(command, cwd):
        if os.name == "nt" and command[0] == npm:
            # Execute npm's JavaScript CLI directly; CreateProcess cannot run npm.cmd.
            node = shutil.which("node")
            cli = Path(npm).parent / "node_modules/npm/bin/npm-cli.js"
            if not node or not cli.is_file():
                raise RuntimeError("Install the official Node.js Windows distribution (including npm).")
            command = [node, str(cli), *command[1:]]
        child = subprocess.Popen(command, cwd=cwd, env=env, start_new_session=True)
        children.append(child)
        return child

    try:
        start([sys.executable, "src/main.py", "--serve"], ROOT)
        start([npm, "run", "dev", "--", "--hostname", "127.0.0.1", "--port", str(web_port)], WEB)
        print("Starting Guardia desktop…", flush=True)
        deadline = time.monotonic() + 120
        while not (responds(f"{env['BACKEND_URL']}/health") and responds(url)):
            if any(child.poll() is not None for child in children):
                raise RuntimeError("A Guardia service exited during startup; see the log above.")
            if time.monotonic() > deadline:
                raise RuntimeError("Guardia services did not become ready within 120 seconds.")
            time.sleep(0.3)
        desktop = start([npm, "run", "electron"], WEB)
        while all(child.poll() is None for child in children):
            time.sleep(0.3)
        if desktop.poll() is None:
            raise RuntimeError("A Guardia service stopped unexpectedly; see the log above.")
        return desktop.returncode
    except KeyboardInterrupt:
        return 0
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1
    finally:
        for child in reversed(children):
            if os.name == "posix":
                # npm may have exited while its descendants are still running.
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            elif child.poll() is None:
                subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"], check=False)
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(child.pid, signal.SIGKILL)
                else:
                    child.kill()
                child.wait()


if __name__ == "__main__":
    sys.exit(main())
