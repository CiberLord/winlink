import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { displayCode, download, isLanAddress, prepareConnection, publicKey, remotePath } from '../dist/ssh.js'

const key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

async function fixture(t) {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'winlink-test-'))
    t.after(() => rm(directory, { recursive: true, force: true }))
    return directory
}

test('only canonical private LAN addresses and valid Ed25519 public keys are accepted', () => {
    assert.ok(isLanAddress('192.168.1.10'))
    assert.ok(isLanAddress('172.31.1.10'))
    for (const invalid of ['172.32.1.10', '192.168.001.10', 'ciberlord.com', '::1', '127.0.0.1']) {
        assert.equal(isLanAddress(invalid), false)
    }
    assert.equal(publicKey(key + ' winlink'), key)
    assert.throws(() => publicKey(key.replace('AAAAC3', 'AAAAA3')), /Ed25519/)
    assert.throws(() => publicKey('command="echo hello" ' + key), /Ed25519/)
    assert.equal(displayCode(key), 'kmYc-vdi2-GkPe-WxB6')
})

test('the OpenSSH configuration pins the entire approved host key', async t => {
    const home = await fixture(t)
    const config = await prepareConnection(home, { address: '192.168.1.10', user: 'standard user', hostKey: key })
    const file = path.join(home, 'ssh_config')
    await writeFile(file, config)
    const resolved = spawnSync('ssh', ['-F', file, '-G', 'winlink-windows'], { encoding: 'utf8' })
    assert.equal(resolved.status, 0)
    assert.match(resolved.stdout, /^stricthostkeychecking true$/m)
    assert.match(resolved.stdout, /^user standard user$/m)
    const known = /^userknownhostsfile (.*)$/m.exec(resolved.stdout)[1]
    assert.equal(await readFile(known, 'utf8'), `winlink-windows ${key}\n`)
    await assert.rejects(() => prepareConnection(home, {
        address: '192.168.1.10', user: 'bad\nProxyCommand', hostKey: key,
    }))
})

test('Windows paths preserve Unicode and reject paths that could split a batch command', () => {
    assert.equal(remotePath('C:\\My Mods\\Мод [test].zip'), 'C:/My Mods/Мод [test].zip')
    assert.equal(remotePath('/C:/My Mods/Мод.zip'), 'C:/My Mods/Мод.zip')
    assert.throws(() => remotePath('c:relative'))
    assert.throws(() => remotePath('C:/bad\nbye'))
})

test('native SFTP downloads a literal Unicode path and preserves existing files', async t => {
    const sftpServer = process.platform === 'darwin' ? '/usr/libexec/sftp-server' : '/usr/lib/openssh/sftp-server'
    try {
        await access(sftpServer)
    } catch {
        t.skip('Native OpenSSH SFTP server is not installed')
        return
    }

    const home = await fixture(t)
    const remote = path.join(home, 'remote')
    const bin = path.join(home, 'bin')
    const local = path.join(home, 'local')
    for (const directory of [remote, bin, local]) await mkdir(directory)
    const originalPath = path.join(remote, 'Мод [a].zip')
    const target = path.join(local, 'Мод копия.zip')
    const original = Buffer.from([0x00, 0xff, 0x0a, 0x35])
    await writeFile(originalPath, original)
    await writeFile(path.join(remote, 'Мод a.zip'), 'wrong')
    const command = `#!${process.execPath}
const fs = require('node:fs');
const cp = require('node:child_process');
const input = fs.readFileSync(0, 'utf8').replace('/C:/', ${JSON.stringify(remote + '/')});
const result = cp.spawnSync('/usr/bin/sftp', ['-q', '-D', ${JSON.stringify(sftpServer)}, '-b', '-'],
    { input, stdio: ['pipe', 'inherit', 'inherit'] });
process.exit(result.status ?? 1);
`
    await writeFile(path.join(bin, 'sftp'), command, { mode: 0o700 })
    const oldPath = process.env.PATH
    process.env.PATH = `${bin}:${oldPath}`
    t.after(() => { process.env.PATH = oldPath })

    await download('unused', 'C:/Мод [a].zip', target, 5)
    const digest = data => createHash('sha256').update(data).digest('hex')
    assert.equal(digest(await readFile(target)), digest(original))
    await assert.rejects(download('unused', 'C:/Мод a.zip', target, 5), { code: 'EEXIST' })
    assert.deepEqual(await readFile(target), original)
    await assert.rejects(download('unused', 'C:/absent.zip', path.join(local, 'missing'), 5), /Download failed/)
    assert.deepEqual(await readdir(local), ['Мод копия.zip'])
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
        error: 'No active profile. Run winlink pair on the Mac first.',
    })
    const log = JSON.parse(await readFile(path.join(home, 'operations.jsonl'), 'utf8'))
    assert.equal(log.command, 'doctor')
    assert.equal(log.ok, false)
})
