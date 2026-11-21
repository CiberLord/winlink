import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { once } from 'node:events'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { certificateCode as windowsCode, startAgent } from '../windows/agent.mjs'
import { certificateCode, discoverCertificate, download, list, powershell, probe, register, upload } from '../dist/transport.js'

async function fixture(t) {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'winlink-test-'))
    t.after(() => rm(directory, { recursive: true, force: true }))
    return directory
}

async function stop(server) {
    if (!server.listening) return
    const closed = new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
    server.closeAllConnections()
    await closed
}

test('authorized HTTPS pairing, certificate pinning, PowerShell and binary files', async t => {
    const home = await fixture(t)
    const root = path.join(home, 'files')
    const stateDirectory = path.join(home, 'state')
    await mkdir(root)
    const options = { address: '127.0.0.1', macIp: '127.0.0.1', stateDirectory, root, listenPort: 0 }
    const agent = await startAgent(options)
    try {
        const certificate = await discoverCertificate(agent.address, agent.port)
        assert.equal(certificateCode(certificate), windowsCode(agent.certificate))
        const server = { address: agent.address, certificate, port: agent.port }
        await assert.rejects(register(server, agent.pairingPin === '00000000' ? '11111111' : '00000000'), /PIN did not match/)
        const unauthorized = await probe({ ...server, user: '', token: '1'.repeat(43) }, 5)
        assert.equal(unauthorized.ok, false)
        assert.match(unauthorized.checks.https.detail, /authentication/)
        const profile = await register(server, agent.pairingPin)
        await assert.rejects(register(server, agent.pairingPin), /Pairing is closed/)
        await assert.rejects(startAgent({ ...options, listenPort: agent.port, pairAgain: true }), { code: 'EADDRINUSE' })
        const status = await probe(profile, 5)
        assert.equal(status.checks.https.ok, true)
        assert.equal(status.checks.files.ok, true)
        if (process.platform === 'win32') {
            assert.equal(status.ok, true)
            const shell = await powershell(profile, "'Привет'; exit 7", 5)
            assert.equal(shell.stdout.trim(), 'Привет')
            assert.equal(shell.exitCode, 7)
            assert.equal((await powershell(profile, 'Start-Sleep -Seconds 5', 1)).timedOut, true)
        }

        const source = path.join(home, 'source')
        const remote = path.join(root, 'Мод [a].zip')
        const destination = path.join(home, 'download')
        const bytes = Buffer.from([0x00, 0xff, 0x0a, 0x35])
        await writeFile(source, bytes)
        await upload(profile, source, remote, 5)
        await writeFile(source, 'replacement')
        await assert.rejects(upload(profile, source, remote, 5), /exist/i)
        await download(profile, remote, destination, 5)
        assert.deepEqual(await readFile(destination), bytes)
        await assert.rejects(download(profile, remote, destination, 5), { code: 'EEXIST' })
        assert.deepEqual(await readdir(root), ['Мод [a].zip'])
        assert.equal((await list(profile, '.', 5))[0].name, 'Мод [a].zip')
        assert.equal((await list(profile, '.', 5))[0].size, bytes.length)

        const different = await startAgent({ ...options, stateDirectory: path.join(home, 'different') })
        try {
            const mismatched = await probe({ ...profile, port: different.port }, 5)
            assert.equal(mismatched.checks.https.ok, false)
            assert.match(mismatched.checks.https.detail, /certificate|verify/i)
        } finally {
            await stop(different.server)
        }

        await stop(agent.server)
        const restarted = await startAgent(options)
        try {
            assert.equal(restarted.pairingPin, null)
            const report = await probe({ ...profile, port: restarted.port }, 5)
            assert.equal(report.checks.https.ok, true)
        } finally {
            await stop(restarted.server)
        }
    } finally {
        await stop(agent.server)
    }
})

test('CLI returns a structured error before pairing', async t => {
    const home = await fixture(t)
    const result = spawnSync(process.execPath, ['dist/cli.js', 'doctor', '--json'], {
        env: { ...process.env, WINLINK_HOME: home },
        encoding: 'utf8',
    })
    assert.equal(result.status, 1)
    assert.deepEqual(JSON.parse(result.stdout), {
        version: 1,
        ok: false,
        error: 'No active profile. Run winlink pair with the Windows IP first.',
    })
    const logfile = await readFile(path.join(home, 'operations.jsonl'), 'utf8')
    const log = JSON.parse(logfile)
    assert.equal(log.command, 'doctor')
    assert.equal(log.ok, false)
})

test('Windows setup.cmd starts the Node agent under the invoking profile', {
    skip: process.platform !== 'win32', timeout: 20_000,
}, async t => {
    const home = await fixture(t)
    const child = spawn('cmd.exe', ['/d', '/c', 'setup.cmd', '127.0.0.1'], {
        env: { ...process.env, LOCALAPPDATA: home },
        stdio: ['ignore', 'pipe', 'pipe'],
    })
    const closed = once(child, 'close')
    let output = ''
    try {
        await new Promise((resolve, reject) => {
            const until = setTimeout(() => reject(new Error('Launcher timed out: ' + output)), 12_000)
            function finish(error) {
                clearTimeout(until)
                if (error) reject(error)
                else resolve()
            }
            child.stdout.on('data', data => {
                output += data
                if (/Pairing PIN \(valid 10 minutes\): \d{8}/.test(output)) finish()
            })
            child.stderr.on('data', data => { output += data })
            child.once('error', finish)
            child.once('exit', code => finish(new Error(`Launcher exited ${code}: ${output}`)))
        })
        const certificate = await discoverCertificate('127.0.0.1')
        assert.match(output, /WinLink is listening/)
        const pin = /Pairing PIN \(valid 10 minutes\): (\d{8})/.exec(output)[1]
        const profile = await register({ address: '127.0.0.1', certificate }, pin)
        assert.equal((await probe(profile, 5)).ok, true)
    } finally {
        if (child.exitCode === null) {
            spawnSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore' })
            child.kill()
        }
        await closed
    }
})
