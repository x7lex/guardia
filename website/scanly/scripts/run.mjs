import { spawn, spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import nextEnv from '@next/env'
import { backendAddress, startBackend } from './backend.mjs'

const require = createRequire(import.meta.url)
const website = fileURLToPath(new URL('../', import.meta.url))
const root = fileURLToPath(new URL('../../../', import.meta.url))
const mode = process.argv[2] || 'dev'
const development = mode !== 'start'
nextEnv.loadEnvConfig(website, development)
const children = new Set()
let stopping = false

function stop(code = 0) {
    if (stopping) return
    stopping = true
    for (const child of children) {
        if (child.exitCode !== null || !child.pid) continue
        if (process.platform === 'win32') {
            spawnSync('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' })
        } else child.kill('SIGTERM')
    }
    process.exit(code)
}
process.on('SIGINT', () => stop())
process.on('SIGTERM', () => stop())

function launch(command, args, env = process.env) {
    const child = spawn(command, args, { cwd: website, env, stdio: 'inherit', windowsHide: true })
    children.add(child)
    child.on('error', error => { console.error(error.message); stop(1) })
    child.on('exit', code => { children.delete(child); stop(code ?? 1) })
    return child
}

try {
    const address = backendAddress(root)
    process.env.BACKEND_URL = address.origin
    const backend = await startBackend(root, address)
    if (backend) {
        children.add(backend)
        backend.on('exit', code => {
            children.delete(backend)
            if (!stopping) console.error('[Guardia] Scanner stopped. See the Python output above.')
            stop(code || 1)
        })
    }
    if (mode === 'desktop') {
        launch(process.execPath, [fileURLToPath(new URL('../node_modules/concurrently/dist/bin/index.js', import.meta.url)), '--kill-others',
            'next dev --port 3000', 'wait-on http-get://localhost:3000 && cross-env NODE_ENV=development electron .'])
    } else {
        if (!['dev', 'start'].includes(mode)) throw new Error(`Unknown mode: ${mode}`)
        launch(process.execPath, [require.resolve('next/dist/bin/next'), mode, ...process.argv.slice(3)])
    }
} catch (error) {
    console.error(`[Guardia] ${error.message}`)
    stop(1)
}
