# Guardia

Guardia is a free and open source project that conducts static analysis on applications, then uses LLM reasoning to classify malware, on-top of a point-based risk assessment.

## Desktop app

Guardia now opens in Electron. Scanning and CLI rescoring do **not** call Gemini.
Use **Review with Gemini** in a report when you want an optional AI opinion.

### Windows installer

The [Windows desktop installer workflow](https://github.com/x7lex/hackthehill3/actions/workflows/windows-desktop.yml)
builds on every push to `main`. Open a successful run and download the
**Guardia-Windows-x64** artifact. Extract it and run
`Guardia-Setup-0.1.0-x64.exe`. It installs a Start menu entry and desktop shortcut.
The installer bundles Electron, the production frontend, and the Python scanner;
users do not need Node.js or Python installed. Targets Windows 10/11 x64.
The installer is currently unsigned, so Windows may show an unknown-publisher warning.

To run from source on Windows, install Python 3.12 (with the `py` launcher) and
Node.js 24 LTS. Double-click `setup-windows.cmd` once, then `run.cmd` to launch.
Setup requires an internet connection to install dependencies.

### macOS/Linux development

With Python 3.12+ and Node.js 22.18+ installed, run from the repository root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
npm ci --prefix hackthehill3-website-final/website/scanly
./run.sh
```

Closing the desktop window stops its local services. Desktop uses loopback ports
3765 and 8765; the source launcher supports `DESKTOP_PORT` and
`DESKTOP_BACKEND_PORT` overrides. Reports persist in Electron's local profile.
Uploaded files are analyzed statically, never executed, and temporary copies are removed.

Browser development remains available with `.venv/bin/python scripts/dev.py` at
`http://localhost:3000`. Optional Gemini credentials belong in the root `.env`
for source development; packaged apps accept `API_TOKEN`/`GEMINI_API_KEY` through
the environment. Credentials and developer `.env` files are excluded from the installer.

### Build a Windows installer locally

Build on Windows x64 (PyInstaller bundles the host platform's Python runtime):

```bat
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements-build.txt
npm ci --prefix hackthehill3-website-final\website\scanly
cd hackthehill3-website-final\website\scanly
npm run dist:win
```

The installer is written to `desktop-dist`. CI tests a real static scan inside
the packaged application before uploading the installer. For local packaged testing:

```bat
set GUARDIA_TEST_EXECUTABLE=desktop-dist/win-unpacked/Guardia.exe
npm run test:desktop
```

The bundled services write startup diagnostics to `services.log` in Electron's
user-data directory (normally `%APPDATA%\Guardia`).

## Risk assessment

Because of a point-based system, Guardia has taken a different design philosophy, instead of classifying whether something is malware or not we have divided it into four groups:

The static risk score is divided into four classifications:

- 0–<3 — Low Risk: Little to no significant suspicious behavior detected.

- 3–<5 — Suspicious: Suspicious characteristics are present and warrant further review.

- 5–<8 — High Risk: Multiple or significant indicators of potentially malicious behavior have been identified.

- 8–10 — Dangerous: Strong indicators of malicious or highly dangerous behavior have been detected.

The browser interface further simplifies these classifications into three broader zones: Safe, Review, and Unsafe.

As technology continues to evolve with the rise of AI, malware has became increasingly more sophisticated overtime, this is an eternal game of cat & mouse as most antimalware/antivirus services run on legacy means of detection.

## Guardia vs Antiviruses

In order to assess the performance of Guardia vs common Antivirus vendors there will be different stages of testing:

- Detection of legacy malware
- Detection of encrypted malware (built to be undetected)
- Assessment of false positives (safe applications but being detected)

## Guardia's Assessment

- **Legacy Malware (Simple Stealer): 3/10 (Use at your own risk)**
  - Because of how the point-based system works, this specific malware isn't doing too much to be flagging, Gemini recommended dynamic analysis after that
- **Encrypted Malware (Simple Stealer): 30% (Use at your own risk)**
  - The deobfuscator is good enough to reveal most of the application as if it were unobfuscated.
- **False Positive Rates: 30% (Use at your own risk)**
  - Context: "hrisitosense.exe" is a CSGO cheat, which tend to have a lot of false positives due to the fact they are designed similarly, but because Guardia doesn't use a black/white classification, it's simply encouraging the user to run at their own risk

## Antivirus Vendor's Assessment (Virustotal)

- **Legacy Malware: 17/70 Positive Detections**
  - [8b4d5221a7848dbc72b4b96bb566caaac12ec4338006bbf7e0b8b32f7f8187c6
    ](https://www.virustotal.com/gui/file/8b4d5221a7848dbc72b4b96bb566caaac12ec4338006bbf7e0b8b32f7f8187c6?nocache=1)

- **Encrypted Malware: 16/70 Positive Detections**
  - [a3d9593d459b8e4004dff22b6d2048100cc912cab37095fda6cff247151cc49f
    ](https://www.virustotal.com/gui/file/a3d9593d459b8e4004dff22b6d2048100cc912cab37095fda6cff247151cc49f?nocache=1)
  - Historically, it's common to see 0/70 detections

- **False Postivie Rates: 26/70 False Detections**
  - [f12316bceefbabe45f8279bd5a9d6e8e815a9f76114097991548ca7e259f6472](https://www.virustotal.com/gui/file/f12316bceefbabe45f8279bd5a9d6e8e815a9f76114097991548ca7e259f6472)
  - Context: "hrisitosense.exe" is a CSGO cheat. Cheats tend to have a lot of false positives due to the fact they are designed similarly to malware, since it's hard to distinguish the two antiviruses commonly flag it.
