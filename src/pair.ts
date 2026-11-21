import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once, EventEmitter } from 'node:events'
import { rm } from 'node:fs/promises'
import { createServer, type IncomingMessage } from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { createInterface } from 'node:readline/promises'
import { promisify } from 'node:util'
import {
    atomicWrite, displayCode, ensureKey, isLanAddress, isWindowsUser,
    prepareConnection, probe, publicKey, type Profile,
} from './ssh.js'

const pairPort = 48765
const pairPath = '/pair/v1'
const pairingTimeout = 15 * 60_000
const exec = promisify(execFile)

export async function localAddress(explicit?: string): Promise<string> {
    const interfaces = Object.entries(os.networkInterfaces()).flatMap(([name, values]) =>
        (values ?? []).filter(value => !value.internal && isLanAddress(value.address))
            .map(value => ({ name, address: value.address })))
    if (explicit) {
        if (interfaces.some(value => value.address === explicit)) return explicit
        throw new Error('--ip must be a private IPv4 address assigned to this Mac')
    }

    if (interfaces.length === 1) return interfaces[0].address
    const ports = await exec('networksetup', ['-listallhardwareports']).catch(() => null)
    const wifi = /Hardware Port: Wi-Fi\r?\nDevice: (\S+)/.exec(ports?.stdout ?? '')?.[1]
    const candidates = interfaces.filter(value => value.name === wifi)
    if (candidates.length === 1) return candidates[0].address

    const choices = interfaces.map(value => `${value.address} (${value.name})`).join(', ')
    throw new Error(choices ? `Choose the Mac's Wi-Fi address with --ip. Available: ${choices}` :
        'No private IPv4 address found. Connect the Mac to Wi-Fi first.')
}

async function readBody(request: IncomingMessage): Promise<Record<string, unknown>> {
    const chunks: Buffer[] = []
    let size = 0
    for await (const chunk of request) {
        size += chunk.length
        if (size > 4096) throw new Error('Pairing request exceeds 4 KiB')
        chunks.push(chunk)
    }
    const body: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new Error('Invalid pairing request')
    return body as Record<string, unknown>
}

export async function pair(home: string, ip?: string): Promise<Profile> {
    if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error('Run winlink pair in an interactive Mac terminal')
    const address = await localAddress(ip)
    const clientKey = await ensureKey(home)
    const nonce = randomUUID()
    const progress = new EventEmitter()
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(new Error('Pairing timed out. Run winlink pair again.')), pairingTimeout)
    const candidateConfig = path.join(home, `pair-${nonce}.conf`)
    const terminal = createInterface({ input: process.stdin, output: process.stdout })
    terminal.on('SIGINT', () => controller.abort(new Error('Pairing cancelled')))
    terminal.once('close', () => controller.abort(new Error('Pairing cancelled')))
    let candidate: Profile | undefined
    let phase: 'waiting' | 'verify' | 'approved' | 'ready' = 'waiting'

    const server = createServer({ requestTimeout: 5_000, headersTimeout: 5_000, maxHeaderSize: 4096 },
        async (request, response) => {
            function reply(status: number, value: unknown) {
                response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
                response.end(JSON.stringify(value))
            }
            try {
                const peer = request.socket.remoteAddress ?? ''
                if (!isLanAddress(peer)) return reply(403, { error: 'LAN IPv4 required' })
                if (request.method === 'GET' && request.url === pairPath && phase === 'waiting') {
                    return reply(200, { nonce, clientKey })
                }
                if (request.method === 'POST' && request.url === pairPath && phase === 'waiting') {
                    const body = await readBody(request)
                    if (phase !== 'waiting' || body.nonce !== nonce || typeof body.user !== 'string'
                        || !isWindowsUser(body.user) || typeof body.hostKey !== 'string') {
                        return reply(400, { error: 'Invalid pairing details' })
                    }
                    candidate = { address: peer, user: body.user, hostKey: publicKey(body.hostKey) }
                    phase = 'verify'
                    reply(200, { ok: true })
                    progress.emit('candidate', candidate)
                    return
                }
                if (request.method === 'GET' && request.url === `${pairPath}/${nonce}` && candidate?.address === peer) {
                    return reply(200, { phase })
                }
                if (request.method === 'POST' && request.url === `${pairPath}/${nonce}/failed` && candidate?.address === peer) {
                    const body = await readBody(request)
                    const detail = typeof body.message === 'string'
                        ? body.message.slice(0, 400).replace(/[\x00-\x1f\x7f-\x9f]/g, ' ').trim()
                        : ''
                    reply(200, { ok: true })
                    controller.abort(new Error(detail ? `Windows setup failed: ${detail}` :
                        'Windows setup failed. See the Windows terminal.'))
                    return
                }
                if (request.method === 'POST' && request.url === `${pairPath}/${nonce}/ready`
                    && phase === 'approved' && candidate?.address === peer) {
                    phase = 'ready'
                    reply(200, { ok: true })
                    progress.emit('ready')
                    return
                }
                reply(404, { error: 'Pairing step unavailable' })
            } catch {
                reply(400, { error: 'Invalid pairing request' })
            }
        })
    server.maxConnections = 8

    try {
        server.listen(pairPort, address)
        await once(server, 'listening', { signal: controller.signal })
        console.log(`Run on Windows from the cloned repository:\n\n  .\\setup.cmd ${address}\n`)
        console.log(`Mac key code: ${displayCode(clientKey)}`)
        const [profile] = await once(progress, 'candidate', { signal: controller.signal }) as [Profile]
        console.log(`Windows ${profile.address} (${profile.user}) key code: ${displayCode(profile.hostKey)}`)
        const answer = await terminal.question('Does the Windows key code match both screens? [y/N] ',
            { signal: controller.signal })
        if (!/^y(es)?$/i.test(answer.trim())) throw new Error('Pairing cancelled. No Windows key was trusted.')

        const config = await prepareConnection(home, profile)
        await atomicWrite(candidateConfig, config)
        phase = 'approved'
        console.log('Waiting for Windows to start OpenSSH…')
        await once(progress, 'ready', { signal: controller.signal })
        const report = await probe(candidateConfig, 20)
        controller.signal.throwIfAborted()
        if (!report.ok) throw new Error(`Windows is configured, but the connection check failed:\n${JSON.stringify(report.checks, null, 2)}`)
        await atomicWrite(path.join(home, 'ssh_config'), config)
        return profile
    } catch (error) {
        if (controller.signal.aborted) throw controller.signal.reason
        if ((error as NodeJS.ErrnoException).code === 'EADDRINUSE') {
            throw new Error(`Pairing port ${pairPort} is in use. Close the other pairing session and retry.`)
        }
        throw error
    } finally {
        clearTimeout(timer)
        terminal.removeAllListeners('close')
        terminal.close()
        server.closeAllConnections()
        if (server.listening) await new Promise<void>(resolve => server.close(() => resolve()))
        await rm(candidateConfig, { force: true })
    }
}
