import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { backendAddress, backendReady, startBackend } from '../scripts/backend.mjs'

test('backend address honors frontend override, process settings, and root .env', t => {
    const root = mkdtempSync(path.join(tmpdir(), 'guardia-config-'))
    t.after(() => rmSync(root, { recursive: true, force: true }))
    assert.equal(backendAddress(root, {}).origin, 'http://127.0.0.1:8000')
    writeFileSync(path.join(root, '.env'), 'BACKEND_HOST=0.0.0.0\nBACKEND_PORT=8123\n')
    assert.equal(backendAddress(root, {}).origin, 'http://127.0.0.1:8123')
    assert.equal(backendAddress(root, { BACKEND_PORT: '8124' }).port, '8124')
    assert.equal(backendAddress(root, { BACKEND_URL: 'http://localhost:9000' }).origin, 'http://localhost:9000')
})

test('reuses a healthy scanner without spawning Python', async t => {
    t.mock.method(globalThis, 'fetch', async () => Response.json({ status: 'ok', max_file_bytes: 100 }))
    assert.equal(await startBackend('/does-not-exist', new URL('http://127.0.0.1:8000')), null)
})

test('rejects unrelated health responses and gives a clear remote-backend error', async t => {
    t.mock.method(globalThis, 'fetch', async () => Response.json({ status: 'ok' }))
    assert.equal(await backendReady('http://127.0.0.1:8000'), false)
    await assert.rejects(startBackend('/unused', new URL('https://scanner.example')), /Check BACKEND_URL/)
})
