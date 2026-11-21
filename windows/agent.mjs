import { execFile } from 'node:child_process'
import { createHash, randomBytes, randomInt, randomUUID, timingSafeEqual, X509Certificate } from 'node:crypto'
import { createReadStream, createWriteStream } from 'node:fs'
import { access, link, mkdir, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises'
import { createServer } from 'node:https'
import { once } from 'node:events'
import { isIPv4 } from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { pipeline } from 'node:stream/promises'
import { fileURLToPath } from 'node:url'
import selfsigned from 'selfsigned'

const port = 48766
const maxScript = 1024 * 1024
const certificateName = 'winlink'
const powerShell = path.join(process.env.SystemRoot ?? 'C:\\Windows',
    'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')

function digest(value) {
    return createHash('sha256').update(value).digest()
}

export function certificateCode(pem) {
    return digest(new X509Certificate(pem).raw).toString('base64').slice(0, 16).match(/.{4}/g).join('-')
}

function validToken(hash, value) {
    return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value) && typeof hash === 'string' &&
        /^[a-f0-9]{64}$/.test(hash) && timingSafeEqual(Buffer.from(hash, 'hex'), digest(value))
}

function isPrivateAddress(ip) {
    if (!isIPv4(ip)) return false
    const [a, b] = ip.split('.').map(Number)
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
        (a === 100 && b >= 64 && b <= 127) || ip === '127.0.0.1'
}

function windowsAddress(macIp) {
    if (!isPrivateAddress(macIp)) throw new Error('Usage: setup.cmd MAC_IP')
    if (macIp === '127.0.0.1') return macIp
    const remote = macIp.split('.').map(Number)
    const candidates = Object.values(os.networkInterfaces()).flat().filter(nic => {
        if (!nic || nic.internal || nic.family !== 'IPv4' || nic.address === macIp) return false
        const mask = nic.netmask.split('.').map(Number)
        return nic.address.split('.').every((part, i) => (Number(part) & mask[i]) === (remote[i] & mask[i]))
    })
    if (candidates.length !== 1) throw new Error('Connect Windows and Mac to the same Wi-Fi and check the Mac IP.')
    return candidates[0].address
}

async function saveIdentity(file, data) {
    const temporary = file + '.' + randomUUID() + '.tmp'
    try {
        await writeFile(temporary, JSON.stringify(data), { mode: 0o600, flag: 'wx' })
        await rename(temporary, file)
    } finally {
        await rm(temporary, { force: true })
    }
}

async function loadIdentity(file) {
    const stored = await readFile(file, 'utf8').catch(error => {
        if (error.code === 'ENOENT') return null
        throw error
    })
    if (stored) {
        const data = JSON.parse(stored)
        const certificate = new X509Certificate(data.certificate)
        if (Date.parse(certificate.validTo) > Date.now()) return { identity: data, created: false }
    }

    const pems = await selfsigned.generate([{ name: 'commonName', value: certificateName }], {
        keyType: 'ec',
        algorithm: 'sha256',
        notBeforeDate: new Date(Date.now() - 5 * 60_000),
        extensions: [
            { name: 'basicConstraints', cA: false },
            { name: 'keyUsage', digitalSignature: true },
            { name: 'subjectAltName', altNames: [{ type: 2, value: certificateName }] },
        ],
    })
    return { identity: { certificate: pems.cert, privateKey: pems.private, client: null }, created: true }
}

class RequestError extends Error {
    constructor(status, message) {
        super(message)
        this.status = status
    }
}

async function readJson(request, limit) {
    const chunks = []
    let size = 0
    for await (const chunk of request.iterator({ destroyOnReturn: false })) {
        size += chunk.length
        if (size > limit) throw new RequestError(413, 'Request is too large.')
        chunks.push(chunk)
    }
    try {
        const value = JSON.parse(Buffer.concat(chunks).toString('utf8'))
        if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error()
        return value
    } catch {
        throw new RequestError(400, 'Expected a JSON object.')
    }
}

function filePath(value, root) {
    if (value === '.' && root) return root
    if (typeof value !== 'string' || !path.isAbsolute(value) || /[\x00-\x1f]/.test(value) ||
        (process.platform === 'win32' && (!/^[A-Za-z]:[\\/]/.test(value) || /[<>:"|?*]/.test(value.slice(2))))) {
        throw new RequestError(400, 'Use an absolute drive path, e.g. C:\\Games\\file.zip.')
    }
    return path.normalize(value)
}

function runPowerShell(script, timeout, cwd, signal) {
    const launcher = "[Console]::InputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); " +
        "$global:OutputEncoding = [Console]::OutputEncoding; $ErrorActionPreference = 'Stop'; $global:LASTEXITCODE = 0; " +
        "$source = [Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($source)); " +
        "if (-not $?) { if ($global:LASTEXITCODE -ne 0) { exit $global:LASTEXITCODE }; exit 1 }"
    const encoded = Buffer.from(launcher, 'utf16le').toString('base64')
    return new Promise((resolve, reject) => {
        const child = execFile(powerShell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-OutputFormat', 'Text',
            '-EncodedCommand', encoded], { cwd, timeout: timeout * 1000, maxBuffer: 8 * 1024 * 1024,
            windowsHide: true, signal }, (error, stdout, stderr) => {
            if (error?.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
                reject(new RequestError(413, 'PowerShell output exceeded 8 MiB.'))
            } else if (error && typeof error.code !== 'number' && !error.killed) {
                reject(error)
            } else {
                resolve({ stdout, stderr, exitCode: error ? (typeof error.code === 'number' ? error.code : 1) : 0,
                    timedOut: !!error?.killed })
            }
        })
        child.stdin?.once('error', () => undefined)
        child.stdin?.end(script)
    })
}

function writeJson(response, status, body) {
    response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' })
    response.end(JSON.stringify(body))
}

async function listDirectory(directory) {
    const entries = await readdir(directory, { withFileTypes: true })
    return Promise.all(entries.map(async entry => {
        const address = path.join(directory, entry.name)
        const metadata = await stat(address).catch(error => {
            if (['ENOENT', 'EACCES', 'EPERM'].includes(error.code)) return undefined
            throw error
        })
        const directoryEntry = metadata ? metadata.isDirectory() : entry.isDirectory()
        return { name: entry.name, path: address, directory: directoryEntry,
            size: directoryEntry ? null : metadata?.size ?? null }
    }))
}

async function upload(request, target) {
    const stage = path.join(path.dirname(target), '.winlink-' + randomUUID() + '.part')
    try {
        await pipeline(request, createWriteStream(stage, { flags: 'wx', mode: 0o600 }))
        await link(stage, target)
    } finally {
        await rm(stage, { force: true })
    }
}

async function uploadOrDownload(request, response, target) {
    if (request.method === 'PUT') {
        await upload(request, target)
        return writeJson(response, 201, { destination: target })
    }
    const metadata = await stat(target)
    if (!metadata.isFile()) throw new RequestError(400, 'Select a regular file.')
    response.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': metadata.size })
    if (metadata.size === 0) response.end()
    else await pipeline(createReadStream(target, { end: metadata.size - 1 }), response)
}

export async function startAgent({ address, macIp, stateDirectory, root = os.homedir(),
    listenPort = port, pairAgain = false }) {
    if (!isPrivateAddress(address) || !isPrivateAddress(macIp)) throw new Error('A private IP address is required.')
    await mkdir(stateDirectory, { mode: 0o700, recursive: true })
    const store = path.join(stateDirectory, 'https.json')
    const { identity, created } = await loadIdentity(store)
    const paired = identity.client?.address === macIp && !pairAgain
    const revoked = !paired && !!identity.client
    if (revoked) identity.client = null
    let pin = paired ? null : String(randomInt(100_000_000)).padStart(8, '0')
    const pairingPin = pin
    const expires = Date.now() + 10 * 60_000
    let attempts = 0
    let runningCommand = false
    let initialized = false

    const server = createServer({
        cert: identity.certificate, key: identity.privateKey, minVersion: 'TLSv1.2',
        headersTimeout: 10_000, requestTimeout: 0, maxHeaderSize: 8192,
    }, async (request, response) => {
        try {
            if (request.socket.remoteAddress !== macIp) throw new RequestError(403, 'Client IP is not allowed.')
            if (!initialized) throw new RequestError(503, 'WinLink is starting.')
            const url = new URL(request.url ?? '/', 'https://winlink')
            if (request.method === 'POST' && url.pathname === '/v1/pair') {
                if (!pin || Date.now() >= expires || attempts >= 5) {
                    throw new RequestError(403, 'Pairing is closed. Restart with -PairAgain to get a new PIN.')
                }
                const body = await readJson(request, 128)
                if (!pin || Date.now() >= expires || attempts >= 5 ||
                    typeof body.pin !== 'string' || !/^\d{8}$/.test(body.pin) ||
                    !timingSafeEqual(Buffer.from(pin), Buffer.from(body.pin))) {
                    attempts++
                    throw new RequestError(403, 'Pairing PIN did not match.')
                }
                pin = null
                const token = randomBytes(32).toString('base64url')
                const client = { address: macIp, tokenHash: digest(token).toString('hex') }
                await saveIdentity(store, { ...identity, client })
                identity.client = client
                return writeJson(response, 201, { token, user: os.userInfo().username })
            }

            const authorization = request.headers.authorization
            if (!authorization?.startsWith('Bearer ') || identity.client?.address !== macIp ||
                !validToken(identity.client?.tokenHash, authorization.slice(7))) {
                throw new RequestError(401, 'WinLink authentication is required.')
            }
            if (request.method === 'GET' && url.pathname === '/v1/health') {
                const shell = await access(powerShell).then(() => true, () => false)
                const files = await access(root).then(() => true, () => false)
                return writeJson(response, 200, { user: os.userInfo().username, powershell: shell, files })
            }
            if (request.method === 'POST' && url.pathname === '/v1/exec') {
                const { script, timeout } = await readJson(request, maxScript)
                if (typeof script !== 'string' || !Number.isInteger(timeout) || timeout < 1 || timeout > 3600) {
                    throw new RequestError(400, 'Invalid PowerShell request.')
                }
                if (runningCommand) throw new RequestError(409, 'A PowerShell command is already running.')
                runningCommand = true
                response.setTimeout((timeout + 5) * 1000)
                const controller = new AbortController()
                response.once('close', () => controller.abort())
                try {
                    return writeJson(response, 200, await runPowerShell(script, timeout, root, controller.signal))
                } finally {
                    runningCommand = false
                }
            }
            if (request.method === 'GET' && url.pathname === '/v1/files') {
                const entries = await listDirectory(filePath(url.searchParams.get('path') ?? '.', root))
                return writeJson(response, 200, entries)
            }
            if (['GET', 'PUT'].includes(request.method) && url.pathname === '/v1/file') {
                return await uploadOrDownload(request, response, filePath(url.searchParams.get('path')))
            }
            throw new RequestError(404, 'WinLink endpoint not found.')
        } catch (error) {
            if (response.destroyed) return
            if (response.headersSent) return response.destroy()
            const statuses = { ENOENT: 404, EEXIST: 409, EACCES: 403, EPERM: 403, ENOTDIR: 400 }
            writeJson(response, error.status ?? statuses[error.code] ?? 500, { error: error.message })
        }
    })
    server.maxConnections = 16
    server.setTimeout(65_000)
    server.on('timeout', socket => socket.destroy())
    server.listen(listenPort, address)
    await once(server, 'listening')
    try {
        if (created || revoked) await saveIdentity(store, identity)
        initialized = true
    } catch (error) {
        server.close()
        server.closeAllConnections()
        throw error
    }
    return { server, address, port: server.address().port, certificate: identity.certificate, pairingPin }
}

async function main() {
    const [macIp, ...options] = process.argv.slice(2)
    if (process.platform !== 'win32') throw new Error('Run the WinLink agent on Windows.')
    if (!macIp || options.some(option => option !== '--pair-again')) throw new Error('Usage: setup.cmd MAC_IP [-PairAgain]')
    if (!process.env.LOCALAPPDATA) throw new Error('LOCALAPPDATA is unavailable. Run WinLink in your Windows profile.')
    const agent = await startAgent({
        macIp, address: windowsAddress(macIp), stateDirectory: path.join(process.env.LOCALAPPDATA, 'WinLink'),
        pairAgain: options.includes('--pair-again'),
    })
    console.log(`WinLink is listening on https://${agent.address}:${agent.port}`)
    console.log(`On the Mac: node dist/cli.js pair ${agent.address}`)
    console.log(`Windows certificate code: ${certificateCode(agent.certificate)}`)
    if (agent.pairingPin) console.log(`Pairing PIN (valid 10 minutes): ${agent.pairingPin}`)
    else console.log('Mac already paired. Run doctor on the Mac.')
    console.log('Keep this window open. Ctrl+C stops WinLink.')
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch(error => {
        console.error(`WinLink: ${error.message}`)
        process.exitCode = 1
    })
}
