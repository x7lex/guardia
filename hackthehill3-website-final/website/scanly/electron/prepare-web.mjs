import { cpSync, existsSync, readdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const output = path.join(root, '.next/standalone');
if (!existsSync(path.join(output, 'server.js'))) throw new Error('Run npm run build first.');
cpSync(path.join(root, 'public'), path.join(output, 'public'), { recursive: true });
cpSync(path.join(root, '.next/static'), path.join(output, '.next/static'), { recursive: true });
// Next may trace local environment files; never ship developer credentials.
for (const entry of readdirSync(output)) {
  if (entry === '.env' || entry.startsWith('.env.')) rmSync(path.join(output, entry));
}
