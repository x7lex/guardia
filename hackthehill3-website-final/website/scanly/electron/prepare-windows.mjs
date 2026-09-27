import { cpSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const root = path.resolve(web, '../../..');
const python = process.env.GUARDIA_PYTHON || path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
run(python, [path.join(root, 'scripts/build_windows_scanner.py')], root);
const output = path.join(root, 'build/windows-web');
rmSync(output, { recursive: true, force: true });
mkdirSync(output, { recursive: true });
cpSync(path.join(web, '.next/standalone'), output, {
  recursive: true,
  filter: source => !['node_modules', '.env'].includes(path.basename(source)) && !path.basename(source).startsWith('.env.'),
});
cpSync(path.join(web, 'public'), path.join(output, 'public'), { recursive: true });
cpSync(path.join(web, '.next/static'), path.join(output, '.next/static'), { recursive: true });
for (const file of ['package.json', 'package-lock.json']) cpSync(path.join(web, file), path.join(output, file));
// Use target-platform Node binaries, rather than the Mac dependencies traced by Next.
if (!process.env.npm_execpath) throw new Error('Run this script using npm run desktop:windows-runtime.');
run(process.execPath, [process.env.npm_execpath, 'ci', '--omit=dev', '--ignore-scripts', '--os=win32', '--cpu=x64', '--no-audit', '--no-fund'], output);
console.log('Windows x64 scanner and web runtime staged.');
