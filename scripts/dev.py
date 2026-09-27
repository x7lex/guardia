"""Start the Python scanner and Next.js together; Ctrl-C stops both."""
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
from urllib.error import URLError
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
    except (OSError, URLError):
        return False


def main():
    load_dotenv(ROOT / ".env", override=False)
    npm = shutil.which("npm")
    website_running = responds("http://127.0.0.1:3000/")
    if port_is_open(3000) and not website_running:
        raise SystemExit("Port 3000 is occupied by an unresponsive process. Stop that process, then run ./run.sh again.")
    scanner_running = responds("http://127.0.0.1:8000/health")
    if port_is_open(8000) and not scanner_running:
        raise SystemExit("Port 8000 is occupied by a service that is not the Guardia scanner.")
    if not website_running and (not npm or not (WEB / "node_modules").is_dir()):
        raise SystemExit("Install Node.js and run npm install in hackthehill3-website-final/website/scanly first.")
    env = os.environ.copy()
    env.setdefault("BACKEND_URL", f"http://127.0.0.1:{env.get('BACKEND_PORT') or '8000'}")
    children = []
    def stop(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        if scanner_running:
            print("Using the existing scanner API on port 8000", flush=True)
        else:
            children.append(subprocess.Popen([sys.executable, "src/main.py", "--serve"], cwd=ROOT, env=env, start_new_session=True))
        if website_running:
            print("Using the existing website at http://localhost:3000; Ctrl-C stops services started by this launcher", flush=True)
        else:
            children.append(subprocess.Popen([npm, "run", "dev"], cwd=WEB, env=env, start_new_session=True))
            print("Guardia web app: http://localhost:3000 — Ctrl-C stops both services", flush=True)
        while all(child.poll() is None for child in children):
            time.sleep(0.3)
        return next((child.returncode for child in children if child.returncode), 0)
    except KeyboardInterrupt:
        return 0
    finally:
        for child in children:
            if child.poll() is None:
                if os.name == "posix":
                    os.killpg(child.pid, signal.SIGTERM)
                else:
                    child.terminate()
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
