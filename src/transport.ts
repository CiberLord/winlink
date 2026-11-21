import { createHash, randomUUID, X509Certificate } from 'node:crypto'
import { createReadStream, createWriteStream } from 'node:fs'
import { link, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import type { IncomingMessage } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { isIPv4 } from 'node:net'
import path from 'node:path'
import { Readable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { connect } from 'node:tls'

export const port = 48766
const tlsName = 'winlink'
const maxJson = 24 * 1024 * 1024

export type Server = { address: string; certificate: string; port?: number }
export type Profile = Server & { token: string; user: string }
export type ProcessResult = { stdout: string; stderr: string; exitCode: number; timedOut: boolean }

export function certificateCode(certificate: string): string {
    return createHash('sha256').update(new X509Certificate(certificate).raw).digest('base64')
        .slice(0, 16).match(/.{4}/g)!.join('-')
}

export function discoverCertificate(address: string, serverPort = port): Promise<string> {
    if (!isIPv4(address)) throw new Error('Use the IPv4 address shown in the WinLink window on Windows.')
    return new Promise((resolve, reject) => {
        // This discovery handshake sends no application data. Pairing separately verifies the displayed fingerprint.
        const socket = connect({ host: address, port: serverPort, servername: tlsName,
            rejectUnauthorized: false, minVersion: 'TLSv1.2' })
        const timer = setTimeout(() => socket.destroy(new Error('Timed out connecting to WinLink on Windows.')), 5_000)
        socket.once('error', reject)
        socket.once('close', () => {
            clearTimeout(timer)
            reject(new Error('The Windows connection closed before sending a certificate.'))
        })
        socket.once('secureConnect', () => {
            const certificate = socket.getPeerCertificate().raw
            if (certificate) resolve(new X509Certificate(certificate).toString())
            else reject(new Error('Windows did not provide a certificate.'))
            socket.destroy()
        })
    })
}

function request(target: Server, method: string, route: string, timeout: number,
    body?: string | Readable, token?: string): Promise<IncomingMessage> {
    return new Promise((resolve, reject) => {
        const certificate = new X509Certificate(target.certificate)
        const headers: Record<string, string | number> = {}
        if (token) headers.Authorization = `Bearer ${token}`
        if (typeof body === 'string') {
            headers['Content-Type'] = 'application/json'
            headers['Content-Length'] = Buffer.byteLength(body)
        } else if (body) {
            headers['Content-Type'] = 'application/octet-stream'
        }
        const req = httpsRequest({
            hostname: target.address, port: target.port ?? port, servername: tlsName, method, path: route,
            ca: target.certificate, minVersion: 'TLSv1.2', agent: false, headers,
            checkServerIdentity: (_, actual) => actual.raw.equals(certificate.raw)
                ? undefined : new Error('The Windows certificate changed. Verify it and pair again.'),
            signal: AbortSignal.timeout(timeout * 1000),
        }, resolve)
        req.once('error', reject)
        if (body instanceof Readable) {
            body.once('error', error => req.destroy(error))
            req.once('close', () => body.destroy())
            body.pipe(req)
        } else {
            req.end(body)
        }
    })
}

async function json(response: IncomingMessage): Promise<unknown> {
    const chunks: Buffer[] = []
    let size = 0
    for await (const chunk of response) {
        size += chunk.length
        if (size > maxJson) throw new Error('WinLink response is too large.')
        chunks.push(chunk)
    }
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    if ((response.statusCode ?? 500) >= 300) {
        throw new Error(typeof body?.error === 'string' ? body.error : `WinLink HTTP ${response.statusCode}`)
    }
    return body
}

async function requestJson(target: Server, method: string, route: string, timeout: number,
    body?: unknown, token?: string): Promise<unknown> {
    return json(await request(target, method, route, timeout, body === undefined ? undefined : JSON.stringify(body), token))
}

export async function register(server: Server, pin: string): Promise<Profile> {
    if (!/^\d{8}$/.test(pin)) throw new Error('Enter the eight-digit PIN shown on Windows.')
    const result = await requestJson(server, 'POST', '/v1/pair', 8, { pin }) as Partial<Profile>
    if (!result.token || !/^[A-Za-z0-9_-]{43}$/.test(result.token) || typeof result.user !== 'string') {
        throw new Error('Windows returned invalid pairing credentials.')
    }
    return { ...server, token: result.token, user: result.user }
}

export async function saveProfile(file: string, profile: Profile): Promise<void> {
    await mkdir(path.dirname(file), { recursive: true, mode: 0o700 })
    const stage = file + '.' + randomUUID() + '.tmp'
    try {
        await writeFile(stage, JSON.stringify(profile), { flag: 'wx', mode: 0o600 })
        await rename(stage, file)
    } finally {
        await rm(stage, { force: true })
    }
}

export async function loadProfile(file: string): Promise<Profile> {
    try {
        return JSON.parse(await readFile(file, 'utf8'))
    } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
        throw new Error('No active profile. Run winlink pair with the Windows IP first.')
    }
}

export async function powershell(profile: Profile, script: string, timeout: number): Promise<ProcessResult> {
    return await requestJson(profile, 'POST', '/v1/exec', timeout + 5, { script, timeout }, profile.token) as ProcessResult
}

export function list(profile: Profile, directory: string, timeout: number): Promise<unknown> {
    return requestJson(profile, 'GET', `/v1/files?path=${encodeURIComponent(directory)}`, timeout, undefined, profile.token)
}

export async function download(profile: Profile, source: string, destination: string, timeout: number): Promise<void> {
    const target = path.resolve(destination)
    const stage = path.join(path.dirname(target), '.winlink-' + randomUUID() + '.part')
    try {
        const response = await request(profile, 'GET', `/v1/file?path=${encodeURIComponent(source)}`, timeout, undefined, profile.token)
        if (response.statusCode !== 200) {
            await json(response)
            throw new Error(`Download failed: HTTP ${response.statusCode}`)
        }
        await pipeline(response, createWriteStream(stage, { flags: 'wx', mode: 0o600 }))
        await link(stage, target)
    } finally {
        await rm(stage, { force: true })
    }
}

export async function upload(profile: Profile, source: string, destination: string, timeout: number): Promise<void> {
    const response = await request(profile, 'PUT', `/v1/file?path=${encodeURIComponent(destination)}`, timeout,
        createReadStream(path.resolve(source)), profile.token)
    await json(response)
}

export async function probe(profile: Profile, timeout: number) {
    const checks: Record<string, { ok: boolean; detail?: string }> = {}
    let user = profile.user
    try {
        const info = await requestJson(profile, 'GET', '/v1/health', timeout, undefined, profile.token) as
            { user: string; powershell: boolean; files: boolean }
        user = info.user
        checks.https = { ok: true }
        checks.powershell = { ok: info.powershell }
        checks.files = { ok: info.files }
    } catch (error) {
        checks.https = { ok: false, detail: (error as Error).message }
    }
    return { address: profile.address, user, checks, ok: Object.values(checks).every(check => check.ok) }
}
