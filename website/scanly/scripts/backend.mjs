import { spawn } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { parseEnv } from 'node:util'

export function backendAddress(root, env = process.env) {
    const file = path.join(root, '.env')
    const settings = existsSync(file) ? parseEnv(readFileSync(file, 'utf8')) : {}
    if (env.BACKEND_URL) return new URL(env.BACKEND_URL)
    const host = env.BACKEND_HOST || settings.BACKEND_HOST || '127.0.0.1'
    const connectHost = host === '0.0.0.0' || host === '::' ? '127.0.0.1' : host
    return new URL(`http://${connectHost.includes(':') ? `[${connectHost}]` : connectHost}:${env.BACKEND_PORT || settings.BACKEND_PORT || '8000'}`)
}

export async function backendReady(url) {
    try {
        const response = await fetch(new URL('/health', url), { signal: AbortSignal.timeout(1000) })
        const body = await response.json()
        return response.ok && body.status === 'ok' && typeof body.max_file_bytes === 'number'
    } catch { return false }
}

export async function startBackend(root, url, env = process.env) {
    root = path.resolve(root)
    if (await backendReady(url)) {
        console.log(`[Guardia] Using scanner at ${url.origin}`)
        return null
    }
    if (url.protocol !== 'http:' || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) {
        throw new Error(`Scanner at ${url.origin} is unreachable. Check BACKEND_URL or start that scanner.`)
    }
    const entry = path.join(root, 'src', 'main.py')
    if (!existsSync(entry)) throw new Error(`Scanner source missing: ${entry}`)
    const venv = path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
    const python = env.PYTHON_PATH || (existsSync(venv) ? venv : process.platform === 'win32' ? 'py' : 'python3')
    const args = python === 'py' ? ['-3', entry, '--serve'] : [entry, '--serve']
    const child = spawn(python, args, {
        cwd: root, windowsHide: true, stdio: ['ignore', 'inherit', 'inherit'],
        env: { ...env, BACKEND_HOST: url.hostname === '[::1]' ? '::1' : '127.0.0.1', BACKEND_PORT: url.port || '80', PYTHONUNBUFFERED: '1' },
    })
    let launchError
    child.on('error', error => { launchError = error })
    const deadline = Date.now() + 30_000
    while (Date.now() < deadline) {
        if (launchError || child.exitCode !== null || child.signalCode !== null) {
            child.kill()
            throw new Error(`Python scanner could not start${launchError ? `: ${launchError.message}` : ` (exit ${child.exitCode})`}. Install requirements.txt into the root .venv, or set PYTHON_PATH to an interpreter with those dependencies. See the Python error above.`)
        }
        if (await backendReady(url)) {
            console.log(`[Guardia] Scanner ready at ${url.origin}`)
            return child
        }
        await new Promise(resolve => setTimeout(resolve, 200))
    }
    child.kill()
    throw new Error(`Scanner did not become ready at ${url.origin} within 30 seconds. Check the Python output and whether the port is already in use.`)
}
