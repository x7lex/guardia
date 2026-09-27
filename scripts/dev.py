"""Start the Python scanner and Next.js together; Ctrl-C stops both."""

import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "hackthehill3-website-final" / "website" / "scanly"


def main():
    load_dotenv(ROOT / ".env", override=False)
    npm = shutil.which("npm")
    if not npm or not (WEB / "node_modules").is_dir():
        raise SystemExit(
            "Install Node.js and run npm install in hackthehill3-website-final/website/scanly first."
        )
    env = os.environ.copy()
    env.setdefault(
        "BACKEND_URL", f"http://127.0.0.1:{env.get('BACKEND_PORT') or '8000'}"
    )
    children = []

    def stop(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    try:
        children.append(
            subprocess.Popen(
                [sys.executable, "src/main.py", "--serve"],
                cwd=ROOT,
                env=env,
                start_new_session=True,
            )
        )
        children.append(
            subprocess.Popen(
                [npm, "run", "dev"], cwd=WEB, env=env, start_new_session=True
            )
        )
        print(
            "Guardia web app: http://localhost:3000 — Ctrl-C stops both services",
            flush=True,
        )
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
