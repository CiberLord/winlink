import { spawn, execFile } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { access, link, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { createConnection, isIPv4 } from 'node:net'
import path from 'node:path'
import { promisify } from 'node:util'

const exec = promisify(execFile)
const alias = 'winlink-windows'
const sshPort = 22
const maxOutput = 8 * 1024 * 1024

export type Profile = { address: string; user: string; hostKey: string }
export type ProcessResult = { stdout: string; stderr: string; exitCode: number; timedOut: boolean }

export function isLanAddress(address: string): boolean {
    if (!isIPv4(address)) return false
    const [a, b] = address.split('.').map(Number)
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
}

export function isWindowsUser(user: string): boolean {
    return /^[\p{L}\p{N}_. -]{1,20}$/u.test(user) && user === user.trim() && !user.startsWith('-')
}

export function publicKey(line: string): string {
    const parts = line.trim().split(/\s+/)
    const wire = Buffer.from(parts[1] ?? '', 'base64')
    const header = Buffer.from('0000000b7373682d6564323535313900000020', 'hex')
    if (parts[0] !== 'ssh-ed25519' || wire.length !== 51 || !wire.subarray(0, 19).equals(header)
        || wire.toString('base64') !== parts[1]) {
        throw new Error('Expected an OpenSSH Ed25519 public key')
    }
    return `ssh-ed25519 ${parts[1]}`
}

export function fingerprint(key: string): string {
    return createHash('sha256').update(Buffer.from(publicKey(key).split(' ')[1], 'base64')).digest('base64')
}

export function displayCode(key: string): string {
    return fingerprint(key).slice(0, 16).match(/.{4}/g)!.join('-')
}

export async function atomicWrite(file: string, content: string): Promise<void> {
    const stage = `${file}.${randomUUID()}.tmp`
    try {
        await writeFile(stage, content, { flag: 'wx', mode: 0o600 })
        await rename(stage, file)
    } finally {
        await rm(stage, { force: true })
    }
}

function configValue(value: string): string {
    if (/[\r\n\0]/.test(value)) throw new Error('Invalid SSH configuration value')
    return '"' + value.replace(/[\\"]/g, '\\$&') + '"'
}

export async function prepareConnection(home: string, profile: Profile): Promise<string> {
    if (!isLanAddress(profile.address) || !isWindowsUser(profile.user)) {
        throw new Error('Invalid Windows connection details')
    }
    const digest = Buffer.from(fingerprint(profile.hostKey), 'base64').toString('hex')
    const knownHosts = path.join(home, `host-${digest}`)
    await atomicWrite(knownHosts, `${alias} ${publicKey(profile.hostKey)}\n`)
    return [
        `Host ${alias}`,
        `    HostName ${profile.address}`,
        `    Port ${sshPort}`,
        `    User ${configValue(profile.user)}`,
        `    HostKeyAlias ${alias}`,
        `    UserKnownHostsFile ${configValue(knownHosts.replaceAll('%', '%%'))}`,
        '    GlobalKnownHostsFile /dev/null',
        `    IdentityFile ${configValue(path.join(home, 'id_ed25519').replaceAll('%', '%%'))}`,
        '    HostKeyAlgorithms ssh-ed25519',
        '    StrictHostKeyChecking yes',
        '    UpdateHostKeys no',
        '    IdentitiesOnly yes',
        '    BatchMode yes',
        '    ForwardAgent no',
        '    ClearAllForwardings yes',
        '    ConnectTimeout 5',
        '    ServerAliveInterval 10',
        '    ServerAliveCountMax 2',
        '',
    ].join('\n')
}

export async function ensureKey(home: string): Promise<string> {
    const file = path.join(home, 'id_ed25519')
    try {
        await access(file)
    } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
        await new Promise<void>((resolve, reject) => {
            const child = spawn('ssh-keygen', ['-q', '-t', 'ed25519', '-C', 'winlink', '-f', file], { stdio: 'inherit' })
            child.once('error', reject)
            child.once('exit', code => code === 0 ? resolve() : reject(new Error('ssh-keygen failed')))
        })
    }
    const key = publicKey(await readFile(file + '.pub', 'utf8').catch(async error => {
        if (error.code !== 'ENOENT') throw error
        return (await exec('ssh-keygen', ['-y', '-f', file])).stdout
    }))
    const loaded = await exec('ssh-add', ['-l']).catch(() => null)
    const print = 'SHA256:' + fingerprint(key).replace(/=+$/, '')
    if (process.env.SSH_AUTH_SOCK && !loaded?.stdout.includes(print)) {
        await new Promise<void>(resolve => {
            const child = spawn('ssh-add', [file], { stdio: 'inherit' })
            child.once('error', () => resolve())
            child.once('exit', () => resolve())
        })
    }
    return key
}

function run(file: string, args: string[], timeout: number, input?: string): Promise<ProcessResult> {
    return new Promise((resolve, reject) => {
        const child = execFile(file, args, {
            timeout: timeout * 1000,
            maxBuffer: maxOutput,
            encoding: 'utf8',
            killSignal: 'SIGKILL',
            env: { ...process.env, LC_ALL: 'C' },
        }, (error, stdout, stderr) => {
            if (error?.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
                reject(new Error(`${file}: output exceeded 8 MiB`))
                return
            }
            if (error && typeof error.code !== 'number' && !error.killed) {
                reject(new Error(`${file}: ${error.code ?? error.message}`))
                return
            }
            resolve({ stdout, stderr, exitCode: !error ? 0 : typeof error.code === 'number' ? error.code : 1,
                timedOut: !!error?.killed && error.signal === 'SIGKILL' })
        })
        child.stdin?.once('error', () => undefined)
        child.stdin?.end(input)
    })
}

export async function powershell(config: string, script: string, timeout: number): Promise<ProcessResult> {
    // Write PowerShell script to stdin so large/Unicode commands avoid cmd.exe argument limits.
    // A fixed launcher reads UTF-8 and runs the script in one PowerShell invocation.
    const launcher = "[Console]::InputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); " +
        "$global:OutputEncoding = [Console]::OutputEncoding; $ErrorActionPreference = 'Stop'; $global:LASTEXITCODE = 0; " +
        "$source = [Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($source)); " +
        "if (-not $?) { if ($global:LASTEXITCODE -ne 0) { exit $global:LASTEXITCODE }; exit 1 }"
    const encoded = Buffer.from(launcher, 'utf16le').toString('base64')
    return run('ssh', ['-F', config, '-T', alias,
        `powershell.exe -NoLogo -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand ${encoded}`], timeout, script)
}

export function literal(value: string): string {
    return "'" + value.replace(/'/g, "''") + "'"
}

export function remotePath(value: string): string {
    const normalized = value.replaceAll('\\', '/').replace(/^\/(?=[A-Za-z]:\/)/, '')
    if (!/^[A-Za-z]:\//.test(normalized) || /[<>:"|?*\u0000-\u001f]/.test(normalized.slice(2))) {
        throw new Error('Use an absolute Windows drive path, e.g. C:\\Mods\\file.zip')
    }
    return normalized
}

function batchPath(value: string): string {
    if (/[\r\n\0]/.test(value)) throw new Error('Path contains a line break or NUL')
    return '"' + value.replace(/[\\"]/g, '\\$&') + '"'
}

function sftp(config: string, command: string, timeout: number): Promise<ProcessResult> {
    return run('sftp', ['-q', '-F', config, '-b', '-', alias], timeout, `@${command}\n`)
}

function check(result: ProcessResult, message: string): string {
    if (result.timedOut) throw new Error(`${message}: timed out`)
    if (result.exitCode !== 0) {
        throw new Error(`${message}: ${result.stderr.trim() || result.stdout.trim() || `exit ${result.exitCode}`}`)
    }
    return result.stdout
}

export async function list(config: string, value: string, timeout: number): Promise<unknown> {
    const target = value === '.' ? value : remotePath(value)
    const script = `$ErrorActionPreference = 'Stop'
        $entries = @(Get-ChildItem -LiteralPath ${literal(target)} -Force | ForEach-Object {
            @{ name = $_.Name; path = $_.FullName; directory = $_.PSIsContainer; size = $_.Length }
        })
        ConvertTo-Json -InputObject $entries -Compress`
    return JSON.parse(check(await powershell(config, script, timeout), 'List failed'))
}

export async function download(config: string, source: string, destination: string, timeout: number): Promise<void> {
    const target = path.resolve(destination)
    const stage = path.join(path.dirname(target), `.winlink-${randomUUID()}.part`)
    try {
        const result = await sftp(config, `get ${batchPath('/' + remotePath(source))} ${batchPath(stage)}`, timeout)
        check(result, 'Download failed')
        await link(stage, target)
    } finally {
        await rm(stage, { force: true })
    }
}

export async function upload(config: string, source: string, destination: string, timeout: number): Promise<void> {
    const target = remotePath(destination)
    const stage = path.posix.join(path.posix.dirname(target), `.winlink-${randomUUID()}.part`)
    try {
        const result = await sftp(config, `put ${batchPath(path.resolve(source))} ${batchPath('/' + stage)}`, timeout)
        check(result, 'Upload failed')
        const script = `$ErrorActionPreference = 'Stop'; [IO.File]::Move(${literal(stage)}, ${literal(target)})`
        check(await powershell(config, script, timeout), 'Could not publish uploaded file')
    } catch (error) {
        const script = `Remove-Item -LiteralPath ${literal(stage)} -Force -ErrorAction SilentlyContinue`
        await powershell(config, script, Math.min(timeout, 5)).catch(() => undefined)
        throw error
    }
}

export async function probe(config: string, timeout: number) {
    const resolved = await exec('ssh', ['-F', config, '-G', alias])
    const address = /^hostname (.+)$/m.exec(resolved.stdout)?.[1]
    if (!address) throw new Error('SSH configuration contains no host address')

    const checks: Record<string, { ok: boolean; detail?: string }> = {}
    try {
        await new Promise<void>((resolve, reject) => {
            const socket = createConnection({ host: address, port: sshPort })
            socket.setTimeout(Math.min(timeout, 5) * 1000, () => socket.destroy(new Error('Connection timed out')))
            socket.once('error', reject)
            socket.once('connect', () => { socket.destroy(); resolve() })
        })
        checks.tcp = { ok: true }
    } catch (error) {
        checks.tcp = { ok: false, detail: (error as Error).message }
        return { address, checks, ok: false }
    }

    const ssh = await run('ssh', ['-F', config, '-T', alias, 'exit 0'], timeout)
    const shell = ssh.exitCode === 0 ? await powershell(config, "'winlink-ok'", timeout) : undefined
    const files = ssh.exitCode === 0 ? await sftp(config, 'pwd', timeout) : undefined
    checks.ssh = { ok: ssh.exitCode === 0, detail: ssh.stderr.trim() || undefined }
    if (shell) checks.powershell = { ok: shell.exitCode === 0 && shell.stdout.trim() === 'winlink-ok',
        detail: shell.stderr.trim() || undefined }
    if (files) checks.sftp = { ok: files.exitCode === 0, detail: files.stderr.trim() || undefined }
    return { address, checks, ok: Object.values(checks).every(check => check.ok) }
}

export async function prepareHome(home: string): Promise<void> {
    await mkdir(home, { recursive: true, mode: 0o700 })
}
