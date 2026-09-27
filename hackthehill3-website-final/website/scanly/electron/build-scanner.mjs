import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const python = process.env.GUARDIA_PYTHON || path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
const result = spawnSync(python, [
  '-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir',
  '--name', 'guardia-scanner', '--distpath', 'dist/scanner',
  '--workpath', 'build/scanner', '--specpath', 'build',
  '--paths', 'src', '--collect-all', 'capstone', '--collect-all', 'lief',
  '--collect-all', 'uvicorn', '--hidden-import', 'yara', 'src/desktop_server.py',
], { cwd: root, stdio: 'inherit' });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
